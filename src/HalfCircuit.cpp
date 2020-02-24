#include "HalfCircuit.h"
using namespace std;

HalfCircuit::HalfCircuit(int k) {
  kappa = k;
  r = Util::randomByte(kappa);

  //Ensuring that the last bit in r is 1
  unsigned char b = (unsigned char) 1;
  r[kappa-1] = r[kappa-1] | b;
}

HalfCircuit::~HalfCircuit() {}

/*
  Adds a new gate and names it with gateName and adds two encodings
  for false and true
*/
vector<CryptoPP::byte*> HalfCircuit::addGate(string gateName) {
  CryptoPP::byte *encF = Util::randomByte(kappa);
  CryptoPP::byte *encT = Util::byteOp(encF, r, "xor", kappa);
  return addGate(gateName, "input", "", "", encF, encT);
}

vector<CryptoPP::byte*> HalfCircuit::addGate(string gateName, string gateType, string gateL, string gateR, CryptoPP::byte *encF, CryptoPP::byte *encT) {
  vector<CryptoPP::byte*> encodings;
  encodings.push_back(encF);
  encodings.push_back(encT);
  gates[gateName] = encodings;

  gatesOutput.clear();
  gatesOutput.push_back(encF);
  gatesOutput.push_back(encT);

  vector<string> info;
  info.push_back(gateType);
  info.push_back(gateL);
  info.push_back(gateR);
  gateInfo[gateName] = info;

  gateOrder.push_back(gateName);
  return encodings;
}

/*
  XOR-gate
*/
void HalfCircuit::addXOR(string inputGateL, string inputGateR, string outputGate) {
  CryptoPP::byte *encF = Util::byteOp(gates[inputGateL].at(0), gates[inputGateR].at(0), "xor", kappa);
  CryptoPP::byte *encT = Util::byteOp(encF, r, "xor", kappa);
  addGate(outputGate, "xor", inputGateL, inputGateR, encF, encT);
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
  string hashInput = Util::byteToString(leftEnc.at(pa), kappa);
  CryptoPP::byte *WGF = (pa*pb) ?
    Util::byteOp(Util::h(hashInput), r, "xor", kappa):
    Util::h(hashInput);

  CryptoPP::byte *WGT = Util::byteOp(WGF, r, "xor", kappa);

  string hashInputF = Util::byteToString(leftEnc.at(0), kappa);
  string hashInputT = Util::byteToString(leftEnc.at(1), kappa);
  CryptoPP::byte *TG = (1*pb) ?
    Util::byteOp(Util::h(hashInputF), Util::h(hashInputT), "xor", kappa):
    Util::byteOp(Util::byteOp(Util::h(hashInputF), Util::h(hashInputT), "xor", kappa), r, "xor", kappa);

  //Evaluator part
  CryptoPP::byte *WEF = Util::h(Util::byteToString(rightEnc.at(pb), kappa));
  CryptoPP::byte *WET = Util::byteOp(WEF, r, "xor", kappa);
  CryptoPP::byte *TE = Util::byteOp(Util::byteOp(rightEnc.at(0), rightEnc.at(1), "xor", kappa), leftEnc.at(0), "xor", kappa);

  //Adding gates
  vector<CryptoPP::byte*> encodings;
  encodings.push_back(TG);
  encodings.push_back(TE);
  andEncodings[outputGate] = encodings;

  CryptoPP::byte *encF = Util::byteOp(WGF, WEF, "xor", kappa);
  CryptoPP::byte *encT = Util::byteOp(encF, r, "xor", kappa);

  addGate(outputGate, "and", inputGateL, inputGateR, encF, encT);
}

/*
  Evaluate circuit
*/
pair<bool, CryptoPP::byte*> HalfCircuit::evaluate(vector<CryptoPP::byte*> inputs) {
  pair<bool, CryptoPP::byte*> output;

  try {
    int i=0;
    for(string gateName : gateOrder) {
      vector<string> info = gateInfo[gateName];
      string gateType = info.at(0);
      string gateL = info.at(1);
      string gateR = info.at(2);

      if(gateType.compare("input") == 0) {
        gatesEvaluated[gateName] = inputs.at(i);
        i++;
      } else if(gateType.compare("xor") == 0) {
        gatesEvaluated[gateName] = Util::byteOp(gatesEvaluated[gateL], gatesEvaluated[gateR], "xor", kappa);
      } else if(gateType.compare("and") == 0) {
        int sa = Util::lsb(gatesEvaluated[gateL], kappa);
        int sb = Util::lsb(gatesEvaluated[gateR], kappa);

        CryptoPP::byte *TG = andEncodings[gateName].at(0);
        CryptoPP::byte *TE = andEncodings[gateName].at(1);
        CryptoPP::byte *Wa = gatesEvaluated[gateL];
        CryptoPP::byte *Wb = gatesEvaluated[gateR];

        CryptoPP::byte *WG = (sa) ?
          Util::h(Util::byteToString(gatesEvaluated[gateL], kappa)):
          Util::byteOp(Util::h(Util::byteToString(Wa, kappa)), TG, "xor", kappa);

        CryptoPP::byte *WE = (sb) ?
          Util::h(Util::byteToString(Wb, kappa)):
          Util::byteOp(Util::h(Util::byteToString(Wb, kappa)), Util::byteOp(TE, Wa, "xor", kappa), "xor", kappa);

        gatesEvaluated[gateName] = Util::byteOp(WG, WE, "xor", kappa);
      } else {
        Util::printl("Error! Invalid gate type");
        output.first = false;
        output.second = Util::randomByte(kappa);
        return output;
      }
    }

    string lastGate = gateOrder.at(gateOrder.size()-1);
    CryptoPP::byte *encodingOutput = gatesEvaluated[lastGate];
    output.first = true;
    output.second = encodingOutput;
  } catch (...) {
    Util::printl("Error! Could not evaluate circuit");
    output.first = false;
    output.second = Util::randomByte(kappa);
  }

  return output;
}

pair<bool, bool> HalfCircuit::decode(CryptoPP::byte* enc) {
  pair<bool, bool> output;
  if(memcmp(enc, gatesOutput.at(0), kappa) == 0) {
    output.first = true;
    output.second = false;
  } else if(memcmp(enc, gatesOutput.at(1), kappa) == 0) {
    output.first = true;
    output.second = true;
  } else {
    output.first = false;
    output.second = false;
  }
  return output;
}
