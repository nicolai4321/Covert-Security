#include "PartyA.h"
using namespace std;

PartyA::PartyA(int x, int kappa, int lambda, osuCrypto::Channel serverChl, osuCrypto::Channel clientChl, CircuitInterface* F) {
  //Generating random seeds and witnesses
  vector<unsigned int> seedsA;
  vector<unsigned int> witnesses;
  for(int j=0; j<lambda; j++) {
    seedsA.push_back(Util::randomInt(0, (INT_MAX-1000000)));
    witnesses.push_back(Util::randomInt(0, INT_MAX));
  }

  //Get the commitments of the seeds from party B
  vector<CryptoPP::byte*> commitmentsB;
  serverChl.recv(commitmentsB);

  //First OT
  vector<array<osuCrypto::block, 2>> otData0(lambda);
  for(int j=0; j<lambda; j++) {
    otData0[j] = { osuCrypto::toBlock(seedsA.at(j)), osuCrypto::toBlock(witnesses.at(j)) };
  }

  osuCrypto::PRNG prng0(osuCrypto::sysRandomSeed()); //TODO: use own seed
  osuCrypto::KosOtExtSender sender;
  sender.sendChosen(otData0, prng0, serverChl);

  //Garbling
  int blockIndexesRequired = ceil(((float) kappa)/((float) sizeof(long)));
  vector<array<osuCrypto::block, 2>> otData1(lambda*GV::n2);
  vector<CircuitInterface*> circuits;
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

      osuCrypto::block block0;
      osuCrypto::block block1;
      for(int x=0; x<blockIndexesRequired; x++) {
        block0[x] = Util::byteToLong(encsB.at(0)+(x*sizeof(long)));
        block1[x] = Util::byteToLong(encsB.at(1)+(x*sizeof(long)));
      }

      otData1[index] = {block0, block1};
    }
  }

  //Second OT
  osuCrypto::PRNG prng1(osuCrypto::sysRandomSeed()); //TODO: use own seed
  sender.sendChosen(otData1, prng1, serverChl);
}

PartyA::~PartyA() {}
