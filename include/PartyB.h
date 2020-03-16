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
#include "NormalCircuit.h"
#include "PartyA.h"
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
    bool checkCommitments(GarbledCircuit* F, vector<osuCrypto::block> decommitmentsEncA, vector<osuCrypto::block> decommitmentsCircuitA, vector<osuCrypto::block> commitmentsEncsA, vector<osuCrypto::block> commitmentsCircuitsA, vector<osuCrypto::block> encsInputsA);
    bool evaluate(GarbledCircuit* F, vector<osuCrypto::block> encsInputsA, vector<osuCrypto::block> encsInputsGammaB);

  protected:

  private:
    int y;
    int kappa;
    int lambda;
    int gamma;
    map<int, int> iv;
    osuCrypto::Channel chl;
    CircuitInterface* circuit;
    EvaluatorInterface* evaluator;
    vector<string> gateOrderB;
    vector<string> outputGatesB;
    map<string, vector<string>> gateInfoB;
};

#endif // PARTYB_H
