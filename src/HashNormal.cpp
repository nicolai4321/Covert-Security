#include "HashNormal.h"
using namespace std;

CryptoPP::byte* HashNormal::hashByte(CryptoPP::byte* plain, int length) {
  CryptoPP::byte* b = new CryptoPP::byte[2*kappa];
  hashFunc.CalculateDigest(b, plain, length);
  return b;
}

string HashNormal::toString() {
  return "normal";
}

HashNormal::HashNormal(int kapp) {
  kappa = kapp;
  hashFunc = CryptoPP::SHAKE128(2*kappa);
}

HashNormal::~HashNormal(){}
