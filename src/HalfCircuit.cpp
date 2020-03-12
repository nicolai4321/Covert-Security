#include "HalfCircuit.h"
using namespace std;

HalfCircuit::HalfCircuit(int k, unsigned int s) {
  kappa = k;
  seed = s;
  r = Util::randomByte(kappa, seed); seed++;

  //Ensuring that the last bit in r is 1
  unsigned char b = (unsigned char) 1;
  r[kappa-1] = r[kappa-1] | b;

  //Constant 0
  CryptoPP::byte *encFZ = Util::randomByte(kappa, seed); seed++;
  CryptoPP::byte *encTZ = Util::byteOp(encFZ, r, "XOR", kappa);
  vector<CryptoPP::byte*> encsZ = addGate(CONST_ZERO, "CONST", "", "", encFZ, encTZ);
  gatesEvaluated[CONST_ZERO] = encsZ.at(0);

  //Constant 1
  CryptoPP::byte *encFO = Util::randomByte(kappa, seed); seed++;
  CryptoPP::byte *encTO = Util::byteOp(encFO, r, "XOR", kappa);
  vector<CryptoPP::byte*> encsO = addGate(CONST_ONE, "CONST", "", "", encFO, encTO);
  gatesEvaluated[CONST_ONE] = encsO.at(1);
}

HalfCircuit::~HalfCircuit() {}

CircuitInterface* HalfCircuit::createInstance(int kappa, int seed) {
  return new HalfCircuit(kappa, seed);
}

/*
  Adds a new gate and names it with gateName and adds two encodings
  for false and true
*/
vector<CryptoPP::byte*> HalfCircuit::addGate(string gateName) {
  CryptoPP::byte *encF = Util::randomByte(kappa, seed); seed++;
  CryptoPP::byte *encT = Util::byteOp(encF, r, "XOR", kappa);
  return addGate(gateName, "INPUT", "", "", encF, encT);
}

/*
  Adds a new gate and names it with gateName and adds two encodings
  for false and true
*/
vector<CryptoPP::byte*> HalfCircuit::addGate(string gateName, string gateType, string gateL, string gateR, CryptoPP::byte *encF, CryptoPP::byte *encT) {
  vector<CryptoPP::byte*> encodings;
  encodings.push_back(encF);
  encodings.push_back(encT);
  gates[gateName] = encodings;

  vector<string> info;
  info.push_back(gateType);
  info.push_back(gateL);
  info.push_back(gateR);
  gateInfo[gateName] = info;

  if(gateType.compare("INPUT") == 0) nrInputGates++;
  gateOrder.push_back(gateName);
  return encodings;
}

/*
  EQ-gate
*/
void HalfCircuit::addEQ(bool b, string outputGate) {
  string constName = (b) ? CONST_ONE : CONST_ZERO;
  addEQW(constName, outputGate);
}

/*
  EQW-gate
*/
void HalfCircuit::addEQW(string inputGate, string outputGate) {
  CryptoPP::byte *encF = Util::byteOp(gates[inputGate].at(0), gates[CONST_ZERO].at(0), "XOR", kappa);
  CryptoPP::byte *encT = Util::byteOp(encF, r, "XOR", kappa);
  addGate(outputGate, "XOR", inputGate, CONST_ZERO, encF, encT);
}

/*
  INV-gate
*/
void HalfCircuit::addINV(string inputGate, string outputGate) {
  CryptoPP::byte *encF = Util::byteOp(gates[inputGate].at(0), gates[CONST_ONE].at(0), "XOR", kappa);
  CryptoPP::byte *encT = Util::byteOp(encF, r, "XOR", kappa);
  addGate(outputGate, "XOR", inputGate, CONST_ONE, encF, encT);
}

/*
  XOR-gate
*/
void HalfCircuit::addXOR(string inputGateL, string inputGateR, string outputGate) {
  CryptoPP::byte *encF = Util::byteOp(gates[inputGateL].at(0), gates[inputGateR].at(0), "XOR", kappa);
  CryptoPP::byte *encT = Util::byteOp(encF, r, "XOR", kappa);
  addGate(outputGate, "XOR", inputGateL, inputGateR, encF, encT);
}

/*
  AND-gate
*/
void HalfCircuit::addAND(string inputGateL, string inputGateR, string outputGate) {
  vector<CryptoPP::byte*> leftEnc = gates[inputGateL];
  vector<CryptoPP::byte*> rightEnc = gates[inputGateR];
  int pa = Util::lsb(leftEnc.at(0), kappa);
  int pb = Util::lsb(rightEnc.at(0), kappa);

  //Generator part
  CryptoPP::byte *waf = leftEnc.at(0);
  CryptoPP::byte *wat = leftEnc.at(1);

  CryptoPP::byte *WGF = (pa*pb) ?
    Util::byteOp(Util::h(leftEnc.at(pa), kappa), r, "XOR", kappa):
    Util::h(leftEnc.at(pa), kappa);

  CryptoPP::byte *WGT = Util::byteOp(WGF, r, "XOR", kappa);

  CryptoPP::byte *TG = (pb) ?
    Util::byteOp(Util::byteOp(Util::h(waf, kappa), Util::h(wat, kappa), "XOR", kappa), r, "XOR", kappa):
    Util::byteOp(Util::h(waf, kappa), Util::h(wat, kappa), "XOR", kappa);

  //Evaluator part
  CryptoPP::byte *wbf = rightEnc.at(0);
  CryptoPP::byte *wbt = rightEnc.at(1);

  CryptoPP::byte *WEF = Util::h(rightEnc.at(pb), kappa);
  CryptoPP::byte *WET = Util::byteOp(WEF, r, "XOR", kappa);
  CryptoPP::byte *TE = Util::byteOp(Util::byteOp(Util::h(wbf, kappa), Util::h(wbt, kappa), "XOR", kappa), waf, "XOR", kappa);

  //Adding gates
  vector<CryptoPP::byte*> encodings;
  encodings.push_back(TG);
  encodings.push_back(TE);
  andEncodings[outputGate] = encodings;

  CryptoPP::byte *encF = Util::byteOp(WGF, WEF, "XOR", kappa);
  CryptoPP::byte *encT = Util::byteOp(encF, r, "XOR", kappa);

  addGate(outputGate, "AND", inputGateL, inputGateR, encF, encT);
}

/*
  Evaluates the circuit and returns a pair
  the boolean is true if the evaluation was successful
  the vector is the output encodings if the evaluation was succesful
*/
pair<bool, vector<CryptoPP::byte*>> HalfCircuit::evaluate(vector<CryptoPP::byte*> inputs) {
  pair<bool, vector<CryptoPP::byte*>> output;
  vector<CryptoPP::byte*> bytes;
  try {
    int i=0;
    for(string gateName : gateOrder) {
      vector<string> info = gateInfo[gateName];
      string gateType = info.at(0);
      string gateL = info.at(1);
      string gateR = info.at(2);

      if(gateType.compare("INPUT") == 0) {
        if(nrInputGates == i) {
          Util::printl("Error! Wrong number of input gates");
          bytes.clear();
          output.first = false;
          output.second = bytes;
          return output;
        }

        gatesEvaluated[gateName] = inputs.at(i);
        i++;
      } else if(gateType.compare("CONST") == 0) {
      } else if(gateType.compare("XOR") == 0) {
        gatesEvaluated[gateName] = Util::byteOp(gatesEvaluated[gateL], gatesEvaluated[gateR], "XOR", kappa);
      } else if(gateType.compare("AND") == 0) {
        int sa = Util::lsb(gatesEvaluated[gateL], kappa);
        int sb = Util::lsb(gatesEvaluated[gateR], kappa);

        CryptoPP::byte *TG = andEncodings[gateName].at(0);
        CryptoPP::byte *TE = andEncodings[gateName].at(1);
        CryptoPP::byte *Wa = gatesEvaluated[gateL];
        CryptoPP::byte *Wb = gatesEvaluated[gateR];

        CryptoPP::byte *WG = (sa) ?
          Util::byteOp(Util::h(Wa, kappa), TG, "XOR", kappa):
          Util::h(Wa, kappa);

        CryptoPP::byte *WE = (sb) ?
          Util::byteOp(Util::h(Wb, kappa), Util::byteOp(TE, Wa, "XOR", kappa), "XOR", kappa):
          Util::h(Wb, kappa);

        gatesEvaluated[gateName] = Util::byteOp(WG, WE, "XOR", kappa);
      } else {
        Util::printl("Error! Invalid gate type");
        bytes.clear();
        output.first = false;
        output.second = bytes;
        return output;
      }
    }

    //gets the output
    for(string gateName : outputGates) {
      CryptoPP::byte *encodingOutput = gatesEvaluated[gateName];
      bytes.push_back(encodingOutput);
    }

    output.first = true;
    output.second = bytes;
  } catch (...) {
    Util::printl("Error! Could not evaluate circuit");
    bytes.clear();
    output.first = false;
    output.second = bytes;
  }
  return output;
}

pair<CryptoPP::byte*, CryptoPP::byte*> HalfCircuit::getConstEnc() {
  pair<CryptoPP::byte*, CryptoPP::byte*> output;
  output.first = gatesEvaluated[CONST_ZERO];
  output.second = gatesEvaluated[CONST_ONE];
  return output;
}

GarbledCircuit* HalfCircuit::exportCircuit() {
  GarbledCircuit *F = new GarbledCircuit();
  F->setKappa(kappa);
  F->setOutputGates(outputGates);
  F->setGateOrder(gateOrder);
  F->setGateInfo(gateInfo);
  F->setConstants(getConstEnc());
  F->setDecodings(getDecodings());
  F->setAndEncodings(andEncodings);
  return F;
}

map<string, vector<CryptoPP::byte*>> HalfCircuit::getAndEncodings() {
  return andEncodings;
}

string HalfCircuit::toString() {
  return "Half circuit";
}


