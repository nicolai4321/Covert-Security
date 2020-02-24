#include "HalfCircuit.h"
using namespace std;

HalfCircuit::HalfCircuit(int k) {
  kappa = k;
  r = Util::randomByte(kappa);

  //ensuring that the last bit in r is 1
  unsigned char b = (unsigned char) 1;
  r[kappa-1] = r[kappa-1] | b;
}

HalfCircuit::~HalfCircuit() {}

/*
  Adds a new gate and names it with gateName and adds two encodings
  for false and true
*/
vector<CryptoPP::byte*> HalfCircuit::addGate(string gateName) {
  return addGate(gateName, "input", "", "");
}

vector<CryptoPP::byte*> HalfCircuit::addGate(string gateName, string gateType, string gateL, string gateR) {
  CryptoPP::byte *encF;
  CryptoPP::byte *encT;

  if(gateType.compare("xor") == 0) {
    encF = Util::byteOp(gates[gateL].at(0), gates[gateR].at(0), "xor", kappa);
    encT = Util::byteOp(encF, r, "xor", kappa);
  } else {
    encF = Util::randomByte(kappa);
    encT = Util::byteOp(encF, r, "xor", kappa);
  }

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
  addGate(outputGate, "xor", inputGateL, inputGateR);
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
      } else {
        cout << "TODO" << endl;
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
