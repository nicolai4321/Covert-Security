#ifndef PARTYB_H
#define PARTYB_H
#include <iostream>
#include "CircuitInterface.h"
#include "cryptlib.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Network/IOService.h"
#include "EvaluatorInterface.h"
#include "GV.h"
#include "libOTe/TwoChooseOne/KosOtExtReceiver.h"
#include "Util.h"
using namespace std;

class PartyB
{
  public:
    PartyB(int y, int kappa, int lambda, osuCrypto::Channel serverChl, osuCrypto::Channel clientChl, EvaluatorInterface* evaluator);
    virtual ~PartyB();

    void startProtocol();
    vector<osuCrypto::block> otSeedsWitnessA(osuCrypto::KosOtExtReceiver* recver, osuCrypto::Channel clientChl);
    vector<osuCrypto::block> otEncodingsB(osuCrypto::KosOtExtReceiver *recver, osuCrypto::Channel clientChl);

  protected:

  private:
    int y;
    int kappa;
    int lambda;
    int gamma;
    int iv = 0;
    osuCrypto::Channel serverChl;
    osuCrypto::Channel clientChl;
    EvaluatorInterface* evaluator;
};

#endif // PARTYB_H
