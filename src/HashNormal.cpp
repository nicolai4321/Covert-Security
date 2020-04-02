#include "HashNormal.h"
using namespace std;

CryptoPP::byte* HashNormal::hashByte(CryptoPP::byte* plain, int length) {
  Util::h(plain, length);
}

HashNormal::HashNormal(){}

HashNormal::~HashNormal(){}
