#include "PartyA.h"
using namespace std;

PartyA::PartyA(int input, int k, int l, osuCrypto::Channel sChl, osuCrypto::Channel cChl, CircuitInterface* cI) {
  x = input;
  kappa = k;
  lambda = l;
  serverChl = sChl;
  clientChl = cChl;
  F = cI;
}

PartyA::~PartyA() {}

/*
  Starts the protocol
*/
void PartyA::startProtocol() {
  //Generating random seeds and witnesses
  vector<unsigned int> seedsA;
  vector<unsigned int> witnesses;
  for(int j=0; j<lambda; j++) {
    seedsA.push_back(Util::randomInt(0, (INT_MAX-1000000))); //TODO
    witnesses.push_back(Util::randomInt(0, INT_MAX));
  }

  //Get the commitments of the seeds from party B
  vector<CryptoPP::byte*> commitmentsB;
  serverChl.recv(commitmentsB);

  //First OT
  osuCrypto::KosOtExtSender sender;
  otSeedsWitnesses(&sender, serverChl, seedsA, witnesses);

  //Garbling
  pair<vector<CircuitInterface*>, vector<array<osuCrypto::block, 2>>> garblingInfo = garbling(F, seedsA);
  vector<CircuitInterface*> circuits = garblingInfo.first;
  vector<array<osuCrypto::block, 2>> otData = garblingInfo.second;

  //Second OT
  osuCrypto::PRNG prng(osuCrypto::sysRandomSeed()); //TODO: use own seed
  sender.sendChosen(otData, prng, serverChl);
}

/*
  Garbling the circuits and prepare the ot data
*/
pair<vector<CircuitInterface*>, vector<array<osuCrypto::block, 2>>> PartyA::garbling(CircuitInterface* F, vector<unsigned int> seedsA) {
  int blockIndexesRequired = ceil(((float) kappa)/((float) sizeof(long)));
  vector<CircuitInterface*> circuits;
  vector<array<osuCrypto::block, 2>> otData(lambda*GV::n2);

  map<int, vector<vector<CryptoPP::byte*>>> encs;
  for(int j=0; j<lambda; j++) {
    CircuitInterface *G = F->createInstance(kappa, seedsA.at(j));
    CircuitReader cr = CircuitReader();
    pair<bool, vector<vector<CryptoPP::byte*>>> import = cr.import(G, GV::filename);

    if(!import.first) {
      string msg = "Error! Could not import circuit";
      cout << msg << endl;
      throw msg;
    }

    circuits.push_back(G);
    encs[j] = import.second;

    for(int i=0; i<GV::n2; i++) {
      int index = i+(j*GV::n2);
      vector<CryptoPP::byte*> encsB = encs[j].at(GV::n1+i);

      //An entry in a block can hold the size of long (8 bytes)
      osuCrypto::block block0;
      osuCrypto::block block1;
      for(int x=0; x<blockIndexesRequired; x++) {
        block0[x] = Util::byteToLong(encsB.at(0)+(x*sizeof(long)));
        block1[x] = Util::byteToLong(encsB.at(1)+(x*sizeof(long)));
      }

      otData[index] = {block0, block1};
    }
  }

  pair<vector<CircuitInterface*>, vector<array<osuCrypto::block, 2>>> output;
  output.first = circuits;
  output.second = otData;
  return output;
}

/*
  First OT-interaction. Sends seedsA and witnesses
*/
void PartyA::otSeedsWitnesses(osuCrypto::KosOtExtSender* sender, osuCrypto::Channel serverChl, vector<unsigned int> seedsA, vector<unsigned int> witnesses) {
  vector<array<osuCrypto::block, 2>> otData(lambda);
  for(int j=0; j<lambda; j++) {
    otData[j] = { osuCrypto::toBlock(seedsA.at(j)), osuCrypto::toBlock(witnesses.at(j)) };
  }

  osuCrypto::PRNG prng(osuCrypto::sysRandomSeed()); //TODO: use own seed
  sender->sendChosen(otData, prng, serverChl);
}
