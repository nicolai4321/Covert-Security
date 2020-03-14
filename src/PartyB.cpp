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
    seedsB.push_back(Util::randomByte(kappa));
  }

  //Commitments of the seeds for party B
  vector<osuCrypto::block> commitmentsB;
  for(int i=0; i<lambda; i++) {
    int r = Util::randomInt(0, numeric_limits<int>::max(), seedsB.at(i), iv); iv++;
    CryptoPP::byte *c = Util::commit(seedsB.at(i), r);
    osuCrypto::block b = Util::byteToBlock(c, 24);
    commitmentsB.push_back(b);
  }

  clientChl.asyncSend(move(commitmentsB));
  cout << "B: has send my commitments" << endl;

  //First OT
  osuCrypto::KosOtExtReceiver recver;
  vector<osuCrypto::block> seedsWitnessA = otSeedsWitnessA(&recver, clientChl);
  cout << "B: has done first OT" << endl;

  //Second OT
  vector<osuCrypto::block> encsInputsGammaB = otEncodingsB(&recver, clientChl);
  cout << "B: has done second OT" << endl;

  //TODO: check party A
  vector<osuCrypto::block> commitmentsEncsInputsA;
  serverChl.recv(commitmentsEncsInputsA);
  cout << "B: has received commitments from other party" << endl;

  //Sends gamma, witness and seeds to other party
  vector<osuCrypto::block> gammaSeedsWitnessBlock;
  gammaSeedsWitnessBlock.push_back(Util::byteToBlock(Util::intToByte(gamma), 4));
  for(int j=0; j<lambda; j++) {
    gammaSeedsWitnessBlock.push_back(seedsWitnessA.at(j));
  }
  clientChl.asyncSend(move(gammaSeedsWitnessBlock));
  cout << "B: has send witness, gamma and seeds" << endl;

  //Receive garbled circuit and input encodings from the other party
  GarbledCircuit *F;
  vector<osuCrypto::block> encsInputsA;

  serverChl.recv(F);
  cout << "B: has received F" << endl;
  serverChl.recv(encsInputsA);
  cout << "B: has received encodings from other party" << endl;

  vector<CryptoPP::byte*> encsInputs;
  for(int j=0; j<GV::n1; j++) {
    encsInputs.push_back(Util::blockToByte(encsInputsA.at(j), kappa));
  }
  for(int j=0; j<GV::n2; j++) {
    encsInputs.push_back(Util::blockToByte(encsInputsGammaB.at(j+(GV::n2*gamma)), kappa));
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
vector<osuCrypto::block> PartyB::otEncodingsB(osuCrypto::KosOtExtReceiver *recver, osuCrypto::Channel clientChl) {
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
  return encB;
}
