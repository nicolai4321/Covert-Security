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
  if(canEdit) {
    CryptoPP::byte *encF = Util::randomByte(kappa);
    CryptoPP::byte *encT = Util::byteOp(encF, r, "xor", kappa);
    return addGate(gateName, "input", "", "", encF, encT);
  } else {
    Util::printl("Error! Circuit cannot be modified");
    return vector<CryptoPP::byte*>();
  }
}

/*
  Adds a new gate and names it with gateName and adds two encodings
  for false and true
*/
vector<CryptoPP::byte*> HalfCircuit::addGate(string gateName, string gateType, string gateL, string gateR, CryptoPP::byte *encF, CryptoPP::byte *encT) {
  if(canEdit) {
    vector<CryptoPP::byte*> encodings;
    encodings.push_back(encF);
    encodings.push_back(encT);
    gates[gateName] = encodings;

    vector<string> info;
    info.push_back(gateType);
    info.push_back(gateL);
    info.push_back(gateR);
    gateInfo[gateName] = info;

    gateOrder.push_back(gateName);
    return encodings;
  } else {
    Util::printl("Error! Circuit cannot be modified");
    return vector<CryptoPP::byte*>();
  }
}

/*
  XOR-gate
*/
void HalfCircuit::addXOR(string inputGateL, string inputGateR, string outputGate) {
  if(canEdit) {
    CryptoPP::byte *encF = Util::byteOp(gates[inputGateL].at(0), gates[inputGateR].at(0), "xor", kappa);
    CryptoPP::byte *encT = Util::byteOp(encF, r, "xor", kappa);
    addGate(outputGate, "xor", inputGateL, inputGateR, encF, encT);
  }
}

/*
  AND-gate
*/
void HalfCircuit::addAND(string inputGateL, string inputGateR, string outputGate) {
  if(canEdit) {
    vector<CryptoPP::byte*> leftEnc = gates[inputGateL];
    vector<CryptoPP::byte*> rightEnc = gates[inputGateR];
    int pa = Util::lsb(leftEnc.at(0), kappa);
    int pb = Util::lsb(rightEnc.at(0), kappa);

    //Generator part
    CryptoPP::byte *waf = leftEnc.at(0);
    CryptoPP::byte *wat = leftEnc.at(1);

    CryptoPP::byte *WGF = (pa*pb) ?
      Util::byteOp(Util::h(leftEnc.at(pa), kappa), r, "xor", kappa):
      Util::h(leftEnc.at(pa), kappa);

    CryptoPP::byte *WGT = Util::byteOp(WGF, r, "xor", kappa);

    CryptoPP::byte *TG = (pb) ?
      Util::byteOp(Util::byteOp(Util::h(waf, kappa), Util::h(wat, kappa), "xor", kappa), r, "xor", kappa):
      Util::byteOp(Util::h(waf, kappa), Util::h(wat, kappa), "xor", kappa);

    //Evaluator part
    CryptoPP::byte *wbf = rightEnc.at(0);
    CryptoPP::byte *wbt = rightEnc.at(1);

    CryptoPP::byte *WEF = Util::h(rightEnc.at(pb), kappa);
    CryptoPP::byte *WET = Util::byteOp(WEF, r, "xor", kappa);
    CryptoPP::byte *TE = Util::byteOp(Util::byteOp(Util::h(wbf, kappa), Util::h(wbt, kappa), "xor", kappa), waf, "xor", kappa);

    //Adding gates
    vector<CryptoPP::byte*> encodings;
    encodings.push_back(TG);
    encodings.push_back(TE);
    andEncodings[outputGate] = encodings;

    CryptoPP::byte *encF = Util::byteOp(WGF, WEF, "xor", kappa);
    CryptoPP::byte *encT = Util::byteOp(encF, r, "xor", kappa);

    addGate(outputGate, "and", inputGateL, inputGateR, encF, encT);
  }
}

/*
  Evaluates the circuit and returns a pair
  the first index is true if the evaluation was successful
  the second index is the output encoding if the evaluation was succesful
*/
pair<bool, CryptoPP::byte*> HalfCircuit::evaluate(vector<CryptoPP::byte*> inputs) {
  pair<bool, CryptoPP::byte*> output;
  if(canEdit) {
    Util::printl("Error! Cannot evaluate before circuit is build");
    output.first = false;
    output.second = Util::randomByte(kappa);
  } else {
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
            Util::byteOp(Util::h(Wa, kappa), TG, "xor", kappa):
            Util::h(Wa, kappa);

          CryptoPP::byte *WE = (sb) ?
            Util::byteOp(Util::h(Wb, kappa), Util::byteOp(TE, Wa, "xor", kappa), "xor", kappa):
            Util::h(Wb, kappa);

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
  }
  return output;
}
