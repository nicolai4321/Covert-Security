#include "PartyB.h"
using namespace std;

PartyB::PartyB(int input, int k, int l, osuCrypto::Channel serverChl, osuCrypto::Channel clientChl) {
  y = input;
  kappa = k;
  lambda = l;
  gamma = Util::randomInt(0, lambda-1);

  //Generating random seeds
  vector<unsigned int> seedsB;
  for(int i=0; i<lambda; i++) {
    seedsB.push_back(Util::randomInt(0, (INT_MAX-1000000)));
  }

  //Commitments of the seeds for party B
  vector<CryptoPP::byte*> commitmentsB;
  for(int i=0; i<lambda; i++) {
    CryptoPP::byte *b = Util::intToByte(seedsB.at(i));
    CryptoPP::byte *c = Util::commit(b, seedsB.at(i));
    commitmentsB.push_back(c);
  }
  clientChl.asyncSend(move(commitmentsB));

  //First OT
  osuCrypto::BitVector b0(lambda);
  for(int j=0; j<lambda; j++) {
    b0[j] = (j==gamma) ? 1 : 0;
  }

  vector<osuCrypto::block> seedsWitnessA(lambda);
  osuCrypto::PRNG prng0(osuCrypto::sysRandomSeed()); //TODO: use own seed
  osuCrypto::KosOtExtReceiver recver;
  recver.receiveChosen(b0, seedsWitnessA, prng0, clientChl);

  //Second OT
  osuCrypto::BitVector b1(lambda*GV::n2);
  string yString = Util::toBitString(y, GV::n2);
  for(int j=0; j<lambda; j++) {
    for(int i=0; i<GV::n2; i++) {
      int index = i+(j*GV::n2);
      if(j==gamma) {
        b1[index] = yString[i];
      } else {
        b1[index] = 0;
      }
    }
  }

  vector<osuCrypto::block> encodingsB(lambda*GV::n2);
  osuCrypto::PRNG prng1(osuCrypto::sysRandomSeed()); //TODO: use own seed
  recver.receiveChosen(b1, encodingsB, prng1, clientChl);

  //Merge bytes
  vector<CryptoPP::byte*> encInputsB;
  int blockIndexesRequired = ceil(((float) kappa)/((float) sizeof(long)));
  for(osuCrypto::block b : encodingsB) {
    CryptoPP::byte *mergedByte = new CryptoPP::byte[kappa];
    for(int i=0; i<blockIndexesRequired; i++) {
      CryptoPP::byte *bytePart = Util::longToByte(b[i]);
      for(int j=0; j<sizeof(long); j++) {
        mergedByte[(i*sizeof(long))+j] = bytePart[j];
      }
    }
    encInputsB.push_back(mergedByte);
  }
}

PartyB::~PartyB() {}
