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
using namespace std;

class PartyA {
  public:
    PartyA(int x, int kappa, int lambda, osuCrypto::Channel serverChl, osuCrypto::Channel clientChl, CircuitInterface* circuit);
    virtual ~PartyA();

    void startProtocol();
    void otSeedsWitnesses(osuCrypto::KosOtExtSender* sender, osuCrypto::Channel serverChl, vector<CryptoPP::byte*> seedsA, vector<CryptoPP::byte*> witnesses, int length);
    pair<vector<CircuitInterface*>, vector<array<osuCrypto::block, 2>>> garbling(CircuitInterface* circuit, vector<CryptoPP::byte*> seedsA);
    bool checkSeedsWitness(vector<CryptoPP::byte*> gammaSeedsWitnessBlock, vector<CryptoPP::byte*> seedsA, vector<CryptoPP::byte*> witnesses);

  protected:

  private:
    int x;
    int kappa;
    int lambda;
    osuCrypto::Channel serverChl;
    osuCrypto::Channel clientChl;
    CircuitInterface *circuit;

    map<int, vector<vector<CryptoPP::byte*>>> encs;
    map<int, vector<vector<CryptoPP::byte*>>> outputEncs;
};

#endif // PARTYA_H
