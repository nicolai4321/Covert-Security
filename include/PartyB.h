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
#include "SocketRecorder.h"
using namespace std;

class PartyB
{
  public:
    PartyB(int y, int kappa, int lambda, osuCrypto::Channel channel, SocketRecorder *socketRecorder, CircuitInterface* circuit, EvaluatorInterface* evaluator);
    virtual ~PartyB();

    bool startProtocol();
    vector<osuCrypto::block> otSeedsWitnessA(osuCrypto::KosOtExtReceiver* recver, osuCrypto::Channel chlOT, vector<CryptoPP::byte*> seedsB, map<unsigned int, unsigned int>* ivB);
    vector<osuCrypto::block> otEncodingsB(osuCrypto::KosOtExtReceiver *recver, osuCrypto::Channel chlOT, vector<CryptoPP::byte*> seedsB, map<unsigned int, unsigned int>* ivB);
    bool checkCommitments(GarbledCircuit* F, vector<osuCrypto::block> decommitmentsEncA, vector<osuCrypto::block> decommitmentsCircuitA, vector<osuCrypto::block> commitmentsEncsA, vector<osuCrypto::block> commitmentsCircuitsA, vector<osuCrypto::block> encsInputsA);
    bool evaluate(GarbledCircuit* F, vector<osuCrypto::block> encsInputsA, vector<osuCrypto::block> encsInputsGammaB);
    bool simulatePartyA(vector<osuCrypto::block> seedsWitnessA, vector<osuCrypto::block> commitmentsEncsA, vector<osuCrypto::block> commitmentsCircuitsA);

  protected:

  private:
    int y;
    int kappa;
    int lambda;
    int gamma;
    osuCrypto::Channel chl;
    osuCrypto::Channel chlOT;
    SocketRecorder *socketRecorder;
    CircuitInterface* circuit;
    EvaluatorInterface* evaluator;
    vector<string> gateOrderB;
    vector<string> outputGatesB;
    map<string, vector<string>> gateInfoB;
    vector<vector<pair<int, unsigned char*>>> transcriptsRecv0;
    vector<vector<pair<int, unsigned char*>>> transcriptsSent0;
    vector<vector<pair<int, unsigned char*>>> transcriptsRecv1;
    vector<vector<pair<int, unsigned char*>>> transcriptsSent1;
};

#endif // PARTYB_H
