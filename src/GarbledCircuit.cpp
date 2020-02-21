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

/*
  Adds a new gate and names it with gateName and adds two encodings
  for false and true
*/
void GarbledCircuit::addGate(string gateName) {
  CryptoPP::byte *encF = Util::randomByte(kappa);
  CryptoPP::byte *encT = Util::randomByte(kappa);

  vector<CryptoPP::byte*> encodings;
  encodings.push_back(encF);
  encodings.push_back(encT);
  gates[gateName] = encodings;
}

/*
  Encryption: E(keyL, iv, E(keyR, iv, m))
*/
string GarbledCircuit::doubleEncrypt(CryptoPP::byte* m, CryptoPP::byte* keyL, CryptoPP::byte* keyR, CryptoPP::byte* iv) {
  string msg = Util::byteToString(m, kappa);
  string cipherText0 = Util::encrypt(msg, keyR, iv);
  string cipherText1 = Util::encrypt(cipherText0, keyL, iv);
  return cipherText1;
}

/*
  Decryption: D(keyR, iv, D(keyL, iv, c))
*/
CryptoPP::byte* GarbledCircuit::doubleDecrypt(string c, CryptoPP::byte* keyL, CryptoPP::byte* keyR, CryptoPP::byte* iv) {
  string clearText0 = Util::decrypt(c, keyL, iv);
  string clearText1 = Util::decrypt(clearText0, keyR, iv);
  CryptoPP::byte *clearTextB = Util::stringToByte(clearText1, kappa);
  return clearTextB;
}

/*
  XOR gate
*/
void GarbledCircuit::addXOR(string inputGateL, string inputGateR, string outputGate) {
  addGate(outputGate);

  CryptoPP::byte *falseEncodingL = gates[inputGateL].at(0);
  CryptoPP::byte *trueEncodingR = gates[inputGateR].at(1);

  CryptoPP::byte *falseEncodingR = gates[inputGateR].at(0);
  CryptoPP::byte *trueEncodingL = gates[inputGateL].at(1);

  CryptoPP::byte *falseEncodingO = gates[outputGate].at(0);
  CryptoPP::byte *trueEncodingO = gates[outputGate].at(1);

  CryptoPP::byte *iv = Util::generateIV();

  vector<string> garbledTable;
  garbledTable.push_back(doubleEncrypt(falseEncodingO, falseEncodingL, falseEncodingR, iv));
  garbledTable.push_back(doubleEncrypt(trueEncodingO, falseEncodingL, trueEncodingR, iv));
  garbledTable.push_back(doubleEncrypt(trueEncodingO, trueEncodingL, falseEncodingR, iv));
  garbledTable.push_back(doubleEncrypt(falseEncodingO, trueEncodingL, trueEncodingR, iv));
  garbledTables[outputGate] = garbledTable;
}
