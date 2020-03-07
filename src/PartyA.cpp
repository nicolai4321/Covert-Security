#include "PartyA.h"
using namespace std;

PartyA::PartyA(int x, int kappa, int lambda, CircuitInterface* F) {
  vector<unsigned int> seedsA;
  vector<string> witnesses;
  for(int i=0; i<lambda; i++) {
    seedsA.push_back(Util::randomInt(0, (INT_MAX-1000000)));
    witnesses.push_back(Util::randomString(kappa));
  }
}

PartyA::~PartyA() {}
