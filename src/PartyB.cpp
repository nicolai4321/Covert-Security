#include "PartyB.h"
using namespace std;

PartyB::PartyB(int input, int k, int l, osuCrypto::Channel sChl, osuCrypto::Channel cChl, EvaluatorInterface* eI) {
  y = input;
  kappa = k;
  lambda = l;
  serverChl = sChl;
  clientChl = cChl;
  evaluator = eI;
}

PartyB::~PartyB() {}

/*
  Starts the protocol
*/
void PartyB::startProtocol() {
  gamma = Util::randomInt(0, lambda-1);

  //Generating random seeds
  vector<CryptoPP::byte*> seedsB;
  for(int i=0; i<lambda; i++) {
    seedsB.push_back(Util::randomByte(Util::SEED_LENGTH));
  }

  //Commitments of the seeds for party B
  vector<CryptoPP::byte*> commitmentsB;
  for(int i=0; i<lambda; i++) {
    int r = Util::randomInt(0, numeric_limits<int>::max(), seedsB.at(i), i);
    CryptoPP::byte *c = Util::commit(seedsB.at(i), r);
    commitmentsB.push_back(c);
  }

  clientChl.asyncSend(move(commitmentsB));
  cout << "B: has send my commitments" << endl;

  //First OT
  osuCrypto::KosOtExtReceiver recver;
  vector<CryptoPP::byte*> seedsWitnessA = otSeedsWitnessA(&recver, clientChl);
  cout << "B: has done first OT" << endl;

  //Second OT
  vector<CryptoPP::byte*> encsInputsGammaB = otEncodingsB(&recver, clientChl);
  cout << "B: has done second OT" << endl;

  //TODO: check party A
  vector<CryptoPP::byte*> commitmentsEncsInputsA;
  serverChl.recv(commitmentsEncsInputsA);
  cout << "B: has received commitments from other party" << endl;

  //Sends gamma, witness and seeds to other party
  vector<CryptoPP::byte*> gammaSeedsWitnessBlock;
  gammaSeedsWitnessBlock.push_back(Util::intToByte(gamma));
  for(int j=0; j<lambda; j++) {
    gammaSeedsWitnessBlock.push_back(seedsWitnessA.at(j));
  }
  clientChl.asyncSend(move(gammaSeedsWitnessBlock));
  cout << "B: has send witness, gamma and seeds" << endl;

  //Receive garbled circuit and input encodings from the other party
  GarbledCircuit *F;
  vector<CryptoPP::byte*> encsInputsA;

  serverChl.recv(F);
  cout << "B: has received F" << endl;
  serverChl.recv(encsInputsA);
  cout << "B: has received encodings from other party" << endl;

  vector<CryptoPP::byte*> encsInputs;
  for(int j=0; j<GV::n1; j++) {
    encsInputs.push_back(encsInputsA.at(j));
  }
  for(int j=0; j<GV::n2; j++) {
    encsInputs.push_back(encsInputsGammaB.at(j+(GV::n2*gamma)));
  }

  evaluator->giveCircuit(F);
  pair<bool, vector<CryptoPP::byte*>> evaluated = evaluator->evaluate(encsInputs);
  if(evaluated.first) {
    pair<bool, vector<bool>> decoded = evaluator->decode(evaluated.second);
    if(decoded.first) {
      vector<bool> output = decoded.second;
      cout << "Output B: ";
      for(bool b : output) {
        cout << b;
      }
      cout << endl;
    } else {
      string msg = "Error! Could not decode circuit";
      cout << msg << endl;
      throw msg;
    }
  } else {
    string msg = "Error! Could not evaluate circuit";
    cout << msg << endl;
    throw msg;
  }
}

/*
  First OT-interaction. Receives seeds and witnesses for A
*/
vector<CryptoPP::byte*> PartyB::otSeedsWitnessA(osuCrypto::KosOtExtReceiver *recver, osuCrypto::Channel clientChl) {
  //Choice bit
  osuCrypto::BitVector b(lambda);
  for(int j=0; j<lambda; j++) {
    b[j] = (j==gamma) ? 1 : 0;
  }

  //Ot
  vector<osuCrypto::block> seedsWitnessA(lambda);
  osuCrypto::PRNG prng(osuCrypto::sysRandomSeed()); //TODO: use own seed
  recver->receiveChosen(b, seedsWitnessA, prng, clientChl);

  /*
  vector<CryptoPP::byte*> seedsWitnessBytes;
  for(int j=0; j<lambda; j++) {
    seedsWitnessBytes.push_back(Util::longToByte(seedsWitnessA.at(j)[0]));
  }

  return seedsWitnessBytes;*/
  return mergeBlocks(seedsWitnessA, kappa);
}

/*
  Second OT-interaction. Receives encodings for own input
*/
vector<CryptoPP::byte*> PartyB::otEncodingsB(osuCrypto::KosOtExtReceiver *recver, osuCrypto::Channel clientChl) {
  //Choice bit
  osuCrypto::BitVector b(lambda*GV::n2);
  string yString = Util::intToBitString(y, GV::n2);
  for(int j=0; j<lambda; j++) {
    for(int i=0; i<GV::n2; i++) {
      int index = i+(j*GV::n2);
      if(j==gamma) {
        int yIndex = (int) yString[i] - 48;
        b[index] = yIndex;
      } else {
        b[index] = 0;
      }
    }
  }

  //Ot
  vector<osuCrypto::block> encB(lambda*GV::n2);
  osuCrypto::PRNG prng(osuCrypto::sysRandomSeed()); //TODO: use own seed
  recver->receiveChosen(b, encB, prng, clientChl);
  return mergeBlocks(encB, kappa);
}

/*
  Merges multiple bytes into one byte
*/
vector<CryptoPP::byte*> PartyB::mergeBlocks(vector<osuCrypto::block> blocks, int length) {
  int blockIndexesRequired = ceil(((float) length)/((float) sizeof(long)));
  vector<CryptoPP::byte*> mergedBytes;
  for(osuCrypto::block b : blocks) {
    CryptoPP::byte *mergedByte = new CryptoPP::byte[length];

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
