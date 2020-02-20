#include <iostream>
#include "GarbledCircuit.h"
#include "Util.h"
#include <string>
#include <vector>
#include <map>
using namespace std;

GarbledCircuit::GarbledCircuit(int k) {
  kappa = k;
}

void GarbledCircuit::addGate(string gateName) {
  CryptoPP::byte *b0 = Util::randomByte(kappa);
  CryptoPP::byte *b1 = Util::randomByte(kappa);

  vector<CryptoPP::byte*> encodings;
  encodings.push_back(b0);
  encodings.push_back(b1);
  gates[gateName] = encodings;
}

void GarbledCircuit::addXOR(string inputGateL, string inputGateR, string outputGate) {
  addGate(outputGate);

  CryptoPP::byte *falseEncodingL = gates[inputGateL].at(0);
  CryptoPP::byte *falseEncodingR = gates[inputGateR].at(0);
  CryptoPP::byte *falseEncodingO = gates[outputGate].at(0);
  CryptoPP::byte *trueEncodingL = gates[inputGateL].at(1);
  CryptoPP::byte *trueEncodingR = gates[inputGateR].at(1);
  CryptoPP::byte *trueEncodingO = gates[outputGate].at(1);
}
