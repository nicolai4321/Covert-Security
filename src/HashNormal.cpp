#include "HashNormal.h"
using namespace std;

CryptoPP::byte *HashNormal::hashByte(CryptoPP::byte *plain, int length) {
  CryptoPP::byte *b = new CryptoPP::byte[CryptoPP::SHA256::DIGESTSIZE];
  hashFunc.CalculateDigest(b, plain, length);
  return b;
}

string HashNormal::toString() {
  return "sha256";
}

HashNormal::HashNormal(int kapp) {
  kappa = kapp;
  hashFunc = CryptoPP::SHA256();
}

HashNormal::~HashNormal(){}
