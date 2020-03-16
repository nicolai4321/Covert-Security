#ifndef PARTYB_H
#define PARTYB_H
#include <iostream>
#include "CircuitInterface.h"
#include "CircuitReader.h"
#include "cryptlib.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Network/IOService.h"
#include "EvaluatorInterface.h"
#include "GarbledCircuit.h"
#include "GV.h"
#include "libOTe/TwoChooseOne/KosOtExtReceiver.h"
#include "Util.h"
using namespace std;

class PartyB
{
  public:
    PartyB(int y, int kappa, int lambda, osuCrypto::Channel channel, CircuitInterface* circuit, EvaluatorInterface* evaluator);
    virtual ~PartyB();

    bool startProtocol();
    vector<osuCrypto::block> otSeedsWitnessA(osuCrypto::KosOtExtReceiver* recver, osuCrypto::Channel clientChl);
    vector<osuCrypto::block> otEncodingsB(osuCrypto::KosOtExtReceiver *recver, osuCrypto::Channel clientChl);

  protected:

  private:
    int y;
    int kappa;
    int lambda;
    int gamma;
    int iv = 0;
    osuCrypto::Channel chl;
    EvaluatorInterface* evaluator;
    vector<string> gateOrderB;
    vector<string> outputGatesB;
    map<string, vector<string>> gateInfoB;
};

#endif // PARTYB_H
