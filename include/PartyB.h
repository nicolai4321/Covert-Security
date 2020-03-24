#ifndef PARTYB_H
#define PARTYB_H
#include <iostream>
#include "CircuitInterface.h"
#include "CircuitReader.h"
#include "cryptlib.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Network/IOService.h"
#include "cryptoTools/Network/Session.h"
#include "EvaluatorInterface.h"
#include "GarbledCircuit.h"
#include "GV.h"
#include "libOTe/TwoChooseOne/KosOtExtReceiver.h"
#include "NormalCircuit.h"
#include "PartyA.h"
#include "Util.h"
#include "Signature.h"
#include "SignatureHolder.h"
#include "SocketRecorder.h"
using namespace std;

class PartyB {
  public:
    PartyB(int y, CryptoPP::DSA::PublicKey pk, int kappa, int lambda, osuCrypto::Channel channel, SocketRecorder *socketRecorder, CircuitInterface* circuit, EvaluatorInterface* evaluator);
    virtual ~PartyB();

    bool startProtocol();
    vector<osuCrypto::block> otSeedsWitnessA(osuCrypto::KosOtExtReceiver* recver, osuCrypto::Channel chlOT, vector<CryptoPP::byte*> seedsB, map<unsigned int, unsigned int>* ivB);
    bool checkCommitments(GarbledCircuit* F, vector<osuCrypto::block> decommitmentsEncA, vector<osuCrypto::block> decommitmentsCircuitA, vector<osuCrypto::block> commitmentsEncsA, vector<osuCrypto::block> commitmentsCircuitsA, vector<osuCrypto::block> encsInputsA);
    bool evaluate(GarbledCircuit* F, vector<osuCrypto::block> encsInputsA, vector<osuCrypto::block> encsInputsGammaB);
    bool simulatePartyA(vector<CryptoPP::byte*> seedsB, vector<SignatureHolder*> signatureHolders, vector<osuCrypto::block> seedsWitnessA, vector<osuCrypto::block> commitmentsEncsA, vector<osuCrypto::block> commitmentsCircuitsA, vector<osuCrypto::block> commitmentsB);

    static vector<osuCrypto::block> otEncodingsB(int y, int lamb, int kappa, int gamm, osuCrypto::KosOtExtReceiver *recver, osuCrypto::Channel chlOT, SocketRecorder *socketRecorder, vector<CryptoPP::byte*> seedsB, map<unsigned int, unsigned int>* ivB, vector<vector<pair<int, unsigned char*>>>* transcriptsSent, vector<vector<pair<int, unsigned char*>>>* transcriptsRecv);

  protected:

  private:
    int y;
    int kappa;
    int lambda;
    int gamma;
    CryptoPP::DSA::PublicKey pk;
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
