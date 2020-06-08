#ifndef PARTYB_H
#define PARTYB_H
#include <iostream>
#include <fstream>
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
#include "Judge.h"
#include "libOTe/TwoChooseOne/KosOtExtReceiver.h"
#include "NormalCircuit.h"
#include "PartyA.h"
#include "Util.h"
#include "Signature.h"
#include "SignatureHolder.h"
#include "SocketRecorder.h"
#include "TimeLog.h"
using namespace std;

class PartyB {
  public:
    PartyB(int y, CryptoPP::RSA::PublicKey pk, int kappa, int lambda, CircuitInterface *circuit, EvaluatorInterface *evaluator, TimeLog *timeLog);

    virtual ~PartyB();

    bool startProtocol(string filename);

    bool checkCommitments(GarbledCircuit* F, vector<osuCrypto::block> decommitmentsEncA, vector<osuCrypto::block> decommitmentsCircuitA,
                          vector<osuCrypto::Commit> commitmentsEncsA, vector<osuCrypto::Commit> commitmentsCircuitsA, vector<osuCrypto::block> encsInputsA);

    bool evaluate(GarbledCircuit* F, vector<osuCrypto::block> encsInputsA, vector<osuCrypto::block> encsInputsGammaB);

    bool simulatePartyA(osuCrypto::IOService *ios,
                        osuCrypto::KosOtExtReceiver *recver,
                        vector<CryptoPP::byte*> seedsB,
                        vector<SignatureHolder*> signatureHolders,
                        vector<CryptoPP::byte*> seedsA,
                        vector<osuCrypto::Commit> commitmentsEncsA,
                        vector<osuCrypto::Commit> commitmentsCircuitsA,
                        vector<osuCrypto::Commit> commitmentsB,
                        vector<osuCrypto::block> decommitmentsB,
                        pair<vector<CircuitInterface*>, map<int, vector<vector<CryptoPP::byte*>>>> garblingInfoSim);

    vector<osuCrypto::block> otSeedsWitnessA(osuCrypto::KosOtExtReceiver* recver, osuCrypto::Channel chlOT, SocketRecorder *socketRecorder,
                                             vector<CryptoPP::byte*> seedsB, map<unsigned int, unsigned int>* ivB);

    static vector<osuCrypto::block> otEncodingsB(osuCrypto::KosOtExtReceiver* recver,
                                                 CryptoPP::OFB_Mode<CryptoPP::AES>::Encryption *prng,
                                                 int y,
                                                 int lambda,
                                                 int kappa,
                                                 int gamm,
                                                 osuCrypto::Channel chlOT,
                                                 SocketRecorder *socketRecorder,
                                                 vector<CryptoPP::byte*> seedsB,
                                                 map<unsigned int, unsigned int>* ivB);

  protected:

  private:
    int y;
    int kappa;
    int lambda;
    int gamma;
    CryptoPP::RSA::PublicKey pk;
    osuCrypto::Channel chl;
    osuCrypto::Channel chlOT;
    SocketRecorder *socketRecorder;
    CircuitInterface* circuit;
    EvaluatorInterface* evaluator;
    vector<string> gateOrderB;
    vector<string> outputGatesB;
    map<string, vector<string>> gateInfoB;
    TimeLog *timeLog;
    CryptoPP::OFB_Mode<CryptoPP::AES>::Encryption prng;
    string filename;
};

#endif // PARTYB_H
