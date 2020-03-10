#include "PartyB.h"
using namespace std;

PartyB::PartyB(int input, int k, int l, osuCrypto::Channel sChl, osuCrypto::Channel cChl) {
  y = input;
  kappa = k;
  lambda = l;
  serverChl = sChl;
  clientChl = cChl;
}

PartyB::~PartyB() {}

/*
  Starts the protocol
*/
void PartyB::startProtocol() {
  gamma = Util::randomInt(0, lambda-1);

  //Generating random seeds
  vector<unsigned int> seedsB;
  for(int i=0; i<lambda; i++) {
    seedsB.push_back(Util::randomInt(0, (INT_MAX-1000000))); //TODO
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
  osuCrypto::KosOtExtReceiver recver;
  vector<osuCrypto::block> seedsWitnessA = otSeedsWitnessA(&recver, clientChl);

  //Second OT
  vector<CryptoPP::byte*> encInputsB = otEncodingsB(&recver, clientChl);
}

/*
  First OT-interaction. Receives seeds and witnesses for A
*/
vector<osuCrypto::block> PartyB::otSeedsWitnessA(osuCrypto::KosOtExtReceiver *recver, osuCrypto::Channel clientChl) {
  //Choice bit
  osuCrypto::BitVector b(lambda);
  for(int j=0; j<lambda; j++) {
    b[j] = (j==gamma) ? 1 : 0;
  }

  //Ot
  vector<osuCrypto::block> seedsWitnessA(lambda);
  osuCrypto::PRNG prng(osuCrypto::sysRandomSeed()); //TODO: use own seed
  recver->receiveChosen(b, seedsWitnessA, prng, clientChl);
  return seedsWitnessA;
}

/*
  Second OT-interaction. Receives encodings for own input
*/
vector<CryptoPP::byte*> PartyB::otEncodingsB(osuCrypto::KosOtExtReceiver *recver, osuCrypto::Channel clientChl) {
  //Choice bit
  osuCrypto::BitVector b(lambda*GV::n2);
  string yString = Util::toBitString(y, GV::n2);
  for(int j=0; j<lambda; j++) {
    for(int i=0; i<GV::n2; i++) {
      int index = i+(j*GV::n2);
      if(j==gamma) {
        b[index] = yString[i];
      } else {
        b[index] = 0;
      }
    }
  }

  //Ot
  vector<osuCrypto::block> encB(lambda*GV::n2);
  osuCrypto::PRNG prng(osuCrypto::sysRandomSeed()); //TODO: use own seed
  recver->receiveChosen(b, encB, prng, clientChl);
  return mergeBytes(encB);
}

/*
  Merges multiple bytes into one byte
*/
vector<CryptoPP::byte*> PartyB::mergeBytes(vector<osuCrypto::block> bytes) {
  vector<CryptoPP::byte*> mergedBytes;
  int blockIndexesRequired = ceil(((float) kappa)/((float) sizeof(long)));
  for(osuCrypto::block b : bytes) {
    CryptoPP::byte *mergedByte = new CryptoPP::byte[kappa];
    for(int i=0; i<blockIndexesRequired; i++) {
      CryptoPP::byte *bytePart = Util::longToByte(b[i]);
      for(int j=0; j<sizeof(long); j++) {
        mergedByte[(i*sizeof(long))+j] = bytePart[j];
      }
    }
    mergedBytes.push_back(mergedByte);
  }
  return mergedBytes;
}
