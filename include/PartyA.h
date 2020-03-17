#ifndef PARTYA_H
#define PARTYA_H
#include <iostream>
#include "CircuitInterface.h"
#include "CircuitReader.h"
#include "cryptlib.h"
#include "cryptoTools/Network/IOService.h"
#include "EvaluatorInterface.h" //TODO: remove
#include "EvaluatorHalf.h" //TODO: remove
#include "GV.h"
#include "libOTe/TwoChooseOne/KosOtExtSender.h"
#include "NormalCircuit.h"
using namespace std;

class PartyA {
  public:
    PartyA(int x, int kappa, int lambda, osuCrypto::Channel channel, CircuitInterface* circuit);
    virtual ~PartyA();

    bool startProtocol();
    void otSeedsWitnesses(osuCrypto::KosOtExtSender* sender, osuCrypto::Channel serverChl, vector<CryptoPP::byte*> seedsA, vector<CryptoPP::byte*> witnesses, int length);
    bool checkSeedsWitness(vector<osuCrypto::block> gammaSeedsWitnessBlock, vector<CryptoPP::byte*> seedsA, vector<CryptoPP::byte*> witnesses);
    vector<osuCrypto::block> getEncsInputA(int gamma, map<int, vector<vector<CryptoPP::byte*>>> encs);
    vector<array<osuCrypto::block, 2>> getEncsInputB(map<int, vector<vector<CryptoPP::byte*>>> encs);
    vector<osuCrypto::block> getDecommitmentsInputA(int gamma, vector<pair<osuCrypto::block, osuCrypto::block>> decommitmentsEncsA);

    static pair<vector<osuCrypto::block>, vector<osuCrypto::block>> commitCircuits(int lambda, int kappa, CircuitInterface *circuit, vector<CryptoPP::byte*> seedsA, map<unsigned int, unsigned int> iv, vector<CircuitInterface*> circuits);
    static pair<vector<osuCrypto::block>, vector<pair<osuCrypto::block, osuCrypto::block>>> commitEncsA(int lambda, int kappa, vector<CryptoPP::byte*> seedsA, map<unsigned  int, unsigned  int> iv, map<int, vector<vector<CryptoPP::byte*>>> encs);
    static pair<vector<CircuitInterface*>, map<int, vector<vector<CryptoPP::byte*>>>> garbling(int lambda, int kappa, CircuitInterface* circuit, vector<CryptoPP::byte*> seedsA);
    static CryptoPP::byte* commitCircuit(int kappa, string type, GarbledCircuit *F, osuCrypto::block decommit);

  protected:

  private:
    int x;
    int kappa;
    int lambda;
    osuCrypto::Channel chl;
    CircuitInterface *circuit;
};

#endif // PARTYA_H
