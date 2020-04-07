#ifndef PARTYA_H
#define PARTYA_H
#include "CircuitInterface.h"
#include "CircuitReader.h"
#include "cryptlib.h"
#include "cryptoTools/Network/IOService.h"
#include "cryptoTools/Network/SocketAdapter.h"
#include "files.h"
#include "filters.h"
#include "GV.h"
#include "iostream"
#include "libOTe/TwoChooseOne/KosOtExtSender.h"
#include "NormalCircuit.h"
#include "Signature.h"
#include "SignatureHolder.h"
#include "SocketRecorder.h"
#include "TimeLog.h"
using namespace std;

class PartyA {
  public:
    PartyA(int x, CryptoPP::ESIGN<CryptoPP::Whirlpool>::PrivateKey sk, CryptoPP::ESIGN<CryptoPP::Whirlpool>::PublicKey pk, int kappa, int lambda, CircuitInterface *circuit, TimeLog *timeLog);
    virtual ~PartyA();

    bool startProtocol();
    bool checkSeedsWitness(vector<osuCrypto::block> gammaSeedsWitnessBlock, vector<CryptoPP::byte*> seedsA, vector<CryptoPP::byte*> witnesses);
    vector<osuCrypto::block> getEncsInputA(int gamma, map<int, vector<vector<CryptoPP::byte*>>> encs);
    vector<osuCrypto::block> getDecommitmentsInputA(int gamma, vector<pair<osuCrypto::block, osuCrypto::block>> decommitmentsEncsA);
    vector<SignatureHolder*> constructSignatures(vector<osuCrypto::block> commitmentsA, vector<osuCrypto::block> commitmentsB, vector<osuCrypto::block> commitmentsEncsInputsA);

    static void otSeedsWitnesses(osuCrypto::KosOtExtSender* sender, int lambda, int kappa, osuCrypto::Channel serverChl, SocketRecorder *socketRecorder, vector<CryptoPP::byte*> seedsA, map<unsigned int, unsigned int>* iv, vector<CryptoPP::byte*> witnesses);
    static void otEncs(osuCrypto::KosOtExtSender* sender, int lambda, int kappa, osuCrypto::Channel c, SocketRecorder *socketRecorder, map<int, vector<vector<CryptoPP::byte*>>> encs, vector<CryptoPP::byte*> seedsA, map<unsigned int, unsigned int>* iv);
    static pair<vector<osuCrypto::block>, vector<osuCrypto::block>> commitCircuits(int lambda, int kappa, CircuitInterface *circuit, vector<CryptoPP::byte*> seedsA, map<unsigned int, unsigned int>* iv, vector<CircuitInterface*> circuits);
    static void auxCommitEncsA(int j, int kapp, CryptoPP::byte* seedA, map<unsigned int, unsigned int>* iv, vector<vector<CryptoPP::byte*>> encs,
                    vector<osuCrypto::block>* commitmentsEncsInputsA, vector<pair<osuCrypto::block, osuCrypto::block>>* decommitmentsEncsA);
    static pair<vector<osuCrypto::block>, vector<pair<osuCrypto::block, osuCrypto::block>>> commitEncsA(int lambda, int kappa, vector<CryptoPP::byte*> seedsA, map<unsigned int, unsigned int>* iv, map<int, vector<vector<CryptoPP::byte*>>> encs);
    static pair<vector<CircuitInterface*>, map<int, vector<vector<CryptoPP::byte*>>>> garbling(int lambda, int kappa, CircuitInterface* circuit, vector<CryptoPP::byte*> seedsA);
    static CryptoPP::byte* commitCircuit(int kappa, string type, GarbledCircuit *F, osuCrypto::block decommit);

    static pair<CryptoPP::byte*,int> constructSignatureByte(int j, int kappa, osuCrypto::block *commitmentA, osuCrypto::block *commitmentB,
                                                            vector<osuCrypto::block> *commitmentsEncsInputsA,
                                                            vector<pair<int, unsigned char*>> *transcriptSent1,
                                                            vector<pair<int, unsigned char*>> *transcriptRecv1,
                                                            vector<pair<int, unsigned char*>> *transcriptSent2,
                                                            vector<pair<int, unsigned char*>> *transcriptRecv2);

  protected:

  private:
    int x;
    int kappa;
    int lambda;
    CryptoPP::ESIGN<CryptoPP::Whirlpool>::PrivateKey sk;
    CryptoPP::ESIGN<CryptoPP::Whirlpool>::PublicKey pk;
    osuCrypto::Channel chl;
    osuCrypto::Channel chlOT;
    SocketRecorder *socketRecorder;
    osuCrypto::IOService *ios;
    CircuitInterface *circuit;
    TimeLog *timeLog;
};

#endif // PARTYA_H
