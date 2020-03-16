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
    pair<vector<CircuitInterface*>, vector<array<osuCrypto::block, 2>>> garbling(CircuitInterface* circuit, vector<CryptoPP::byte*> seedsA);
    bool checkSeedsWitness(vector<osuCrypto::block> gammaSeedsWitnessBlock, vector<CryptoPP::byte*> seedsA, vector<CryptoPP::byte*> witnesses);
    vector<osuCrypto::block> getEncsInputA(int gamma);
    vector<osuCrypto::block> getDecommitmentsInputA(int gamma, vector<pair<osuCrypto::block, osuCrypto::block>> decommitmentsEncsA);
    pair<vector<osuCrypto::block>, vector<pair<osuCrypto::block, osuCrypto::block>>> commitEncsA(vector<CryptoPP::byte*> seedsA, map<int, int> iv, map<int, vector<vector<CryptoPP::byte*>>> encodings);
    pair<vector<osuCrypto::block>, vector<osuCrypto::block>> commitCircuits(vector<CryptoPP::byte*> seedsA, map<int, int> iv, vector<CircuitInterface*> circuits);

    static CryptoPP::byte* commitCircuit(int kappa, string type, GarbledCircuit *F, osuCrypto::block decommit);

  protected:

  private:
    int x;
    int kappa;
    int lambda;
    osuCrypto::Channel chl;
    CircuitInterface *circuit;

    map<int, vector<vector<CryptoPP::byte*>>> encs;
    map<int, vector<vector<CryptoPP::byte*>>> outputEncs;
};

#endif // PARTYA_H
