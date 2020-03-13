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
    vector<CryptoPP::byte*> otSeedsWitnessA(osuCrypto::KosOtExtReceiver* recver, osuCrypto::Channel clientChl);
    vector<CryptoPP::byte*> otEncodingsB(osuCrypto::KosOtExtReceiver *recver, osuCrypto::Channel clientChl);
    vector<CryptoPP::byte*> mergeBlocks(vector<osuCrypto::block> bytes, int length);

  protected:

  private:
    int y;
    int kappa;
    int lambda;
    int gamma;
    osuCrypto::Channel serverChl;
    osuCrypto::Channel clientChl;
    EvaluatorInterface* evaluator;
};

#endif // PARTYB_H
