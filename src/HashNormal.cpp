#include "HashNormal.h"
using namespace std;

void HashNormal::hashByte(CryptoPP::byte *plain, int plainLength, CryptoPP::byte *outputByte, int outputLength) {
  hashFunc.Update(plain, plainLength);
  hashFunc.TruncatedFinal(outputByte, outputLength);
}

string HashNormal::toString() {
  return "sha256";
}

HashNormal::HashNormal(int kapp) {
  kappa = kapp;
  hashFunc = CryptoPP::SHA256();
}

HashNormal::~HashNormal(){}
