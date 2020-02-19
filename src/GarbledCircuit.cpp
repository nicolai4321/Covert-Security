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

vector<string> GarbledCircuit::addGate(string gateName) {
  vector<string> encodings;
  encodings.push_back(Util::randomString(kappa));
  encodings.push_back(Util::randomString(kappa));
  gates[gateName] = encodings;
  return encodings;
}

void GarbledCircuit::addXOR(string inputGateL, string inputGateR, string outputGate) {
  addGate(outputGate);

  string falseEncodingL = gates[inputGateL].at(0);
  string falseEncodingR = gates[inputGateR].at(0);
  string falseEncodingO = gates[outputGate].at(0);
  string trueEncodingL = gates[inputGateL].at(1);
  string trueEncodingR = gates[inputGateR].at(1);
  string trueEncodingO = gates[outputGate].at(1);

  CryptoPP::byte b0[kappa];
  Util::h(falseEncodingL+falseEncodingR, b0);
  //CryptoPP::byte cc = Util::randomByte(kappa);
  //(*b0) ^ cc;

  CryptoPP::byte b1[kappa];
  Util::h(falseEncodingL+trueEncodingR, b0);

  CryptoPP::byte b2[kappa];
  Util::h(trueEncodingL+falseEncodingR, b0);

  CryptoPP::byte b3[kappa];
  Util::h(trueEncodingL+trueEncodingR, b0);

  //CryptoPP::byte b8[2*CryptoPP::SHA256::DIGESTSIZE];
  //Util::mergeBytes(b8, b0, b1, CryptoPP::SHA256::DIGESTSIZE);
  CryptoPP::byte ran[kappa];
  Util::randomByte(ran, kappa);

  CryptoPP::byte ran2[kappa];
  Util::randomByte(ran2, kappa);

  Util::printByte(ran, kappa);
  Util::printByte(ran2, kappa);

  vector<CryptoPP::byte> garbledTable;
  //garbledTable.push_back(Util::h(falseEncodingL+falseEncodingR, ));

}
