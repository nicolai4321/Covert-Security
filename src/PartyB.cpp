#include "PartyB.h"
using namespace std;

PartyB::PartyB(int input, int k, int l) {
  y = input;
  kappa = k;
  lambda = l;

  vector<int> seedsB;
  for(int i=0; i<lambda; i++) {
    seedsB.push_back(Util::randomInt(0, (INT_MAX-1000000)));
  }

  //commit
  vector<CryptoPP::byte*> commitmentsB;
  for(int i=0; i<lambda; i++) {
    CryptoPP::byte *b = Util::intToByte(seedsB.at(i));
    CryptoPP::byte *c = Util::commit(b, seedsB.at(i));
    commitmentsB.push_back(c);
  }

  gamma = Util::randomInt(0, lambda-1);
}

PartyB::~PartyB() {}
