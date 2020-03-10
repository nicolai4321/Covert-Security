#ifndef PARTYA_H
#define PARTYA_H
#include <iostream>
#include "CircuitInterface.h"
#include "CircuitReader.h"
#include "cryptlib.h"
#include "cryptoTools/Network/IOService.h"
#include "GV.h"
#include "libOTe/TwoChooseOne/KosOtExtSender.h"
using namespace std;

class PartyA
{
  public:
    PartyA(int x, int kappa, int lambda, osuCrypto::Channel serverChl, osuCrypto::Channel clientChl, CircuitInterface* F);
    virtual ~PartyA();

    void startProtocol();
    void otSeedsWitnesses(osuCrypto::KosOtExtSender* sender, osuCrypto::Channel serverChl, vector<unsigned int> seedsA, vector<unsigned int> witnesses);
    pair<vector<CircuitInterface*>, vector<array<osuCrypto::block, 2>>> garbling(CircuitInterface* F, vector<unsigned int> seedsA);

  protected:

  private:
    int x;
    int kappa;
    int lambda;
    osuCrypto::Channel serverChl;
    osuCrypto::Channel clientChl;
    CircuitInterface *F;
};

#endif // PARTYA_H
