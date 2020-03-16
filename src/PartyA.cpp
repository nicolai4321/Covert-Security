#include "PartyA.h"
using namespace std;

PartyA::PartyA(int input, int k, int l, osuCrypto::Channel c, CircuitInterface* cI) {
  x = input;
  kappa = k;
  lambda = l;
  chl = c;
  circuit = cI;
}

PartyA::~PartyA() {}

/*
  Starts the protocol
*/
bool PartyA::startProtocol() {
  //Generating random seeds and witnesses
  vector<CryptoPP::byte*> seedsA;
  vector<CryptoPP::byte*> witnesses;
  for(int j=0; j<lambda; j++) {
    seedsA.push_back(Util::randomByte(kappa));
    witnesses.push_back(Util::randomByte(kappa));
  }

  //Get the commitments of the seeds from party B
  vector<osuCrypto::block> commitmentsB;
  chl.recv(commitmentsB);
  cout << "A: has received commitments from other party" << endl;

  //First OT
  osuCrypto::KosOtExtSender sender;
  otSeedsWitnesses(&sender, chl, seedsA, witnesses, kappa);
  cout << "A: has done first OT" << endl;

  //Garbling
  pair<vector<CircuitInterface*>, vector<array<osuCrypto::block, 2>>> garblingInfo = garbling(circuit, seedsA);
  vector<CircuitInterface*> circuits = garblingInfo.first;
  vector<array<osuCrypto::block, 2>> otData = garblingInfo.second;

  //Second OT
  osuCrypto::PRNG prng(osuCrypto::sysRandomSeed()); //TODO: use own seed
  sender.sendChosen(otData, prng, chl);
  cout << "A: has done second OT" << endl;

  //*************************************
  //TODO: send commitments and auth.
  //*************************************
  //Commitments

  //Input encodings
  vector<pair<osuCrypto::block, osuCrypto::block>> decommitmentsEncsA;
  vector<osuCrypto::block> decommitmentsA;

  vector<osuCrypto::block> commitmentsEncsInputsA;
  for(int j=0; j<lambda; j++) {
    for(int i=0; i<GV::n1; i++) {
      osuCrypto::block decommit0 = Util::byteToBlock(Util::randomByte(kappa, seedsA.at(j), iv), kappa); iv++;
      osuCrypto::block decommit1 = Util::byteToBlock(Util::randomByte(kappa, seedsA.at(j), iv), kappa); iv++;
      CryptoPP::byte *c0 = Util::commit(Util::byteToBlock(encs[j].at(i).at(0), kappa), decommit0);
      CryptoPP::byte *c1 = Util::commit(Util::byteToBlock(encs[j].at(i).at(1), kappa), decommit1);
      pair<osuCrypto::block, osuCrypto::block> p;
      p.first = decommit0;
      p.second = decommit1;
      decommitmentsEncsA.push_back(p);

      //Random order so that party B cannot extract my input when I give him decommitments
      if(Util::randomInt(0, 1) == 0) {
        commitmentsEncsInputsA.push_back(Util::byteToBlock(c0, Util::COMMIT_LENGTH));
        commitmentsEncsInputsA.push_back(Util::byteToBlock(c1, Util::COMMIT_LENGTH));
      } else {
        commitmentsEncsInputsA.push_back(Util::byteToBlock(c1, Util::COMMIT_LENGTH));
        commitmentsEncsInputsA.push_back(Util::byteToBlock(c0, Util::COMMIT_LENGTH));
      }
    }
  }

  //Main commitment
  vector<osuCrypto::block> commitmentsA;
  for(int j=0; j<lambda; j++) {
    GarbledCircuit *F = circuits.at(j)->exportCircuit();

    vector<CryptoPP::byte*> commitQueue;
    pair<CryptoPP::byte*, CryptoPP::byte*> p = F->getConstants();
    commitQueue.push_back(p.first);
    commitQueue.push_back(p.second);
    for(vector<CryptoPP::byte*> v : F->getDecodings()) {
      commitQueue.push_back(v.at(0));
      commitQueue.push_back(v.at(1));
    }
    osuCrypto::block decommit = Util::byteToBlock(Util::randomByte(kappa, seedsA.at(j), iv), kappa); iv++;
    decommitmentsA.push_back(decommit);
    CryptoPP::byte *c = Util::commit(commitQueue, decommit, kappa);

    commitmentsA.push_back(Util::byteToBlock(c, Util::COMMIT_LENGTH));
  }
  cout << "A: sending commitments" << endl;
  chl.asyncSend(move(commitmentsEncsInputsA));
  cout << "A: sending commitments" << endl;
  chl.asyncSend(move(commitmentsA));
  //*************************************0
  //TODO: end
  //*************************************

  //Receive gamma, seeds and witness
  vector<osuCrypto::block> gammaSeedsWitnessBlock;
  chl.recv(gammaSeedsWitnessBlock);
  cout << "A: has received gamma, seeds and witness" << endl;
  int gamma = Util::byteToInt(Util::blockToByte(gammaSeedsWitnessBlock.at(0), 4));

  //Checks the seeds and witness
  if(!checkSeedsWitness(gammaSeedsWitnessBlock, seedsA, witnesses)) {return false;}

  //Send garbled circuit, encoding inputs, commitments and decommitments to other party
  CircuitInterface *circuit = circuits.at(gamma);
  GarbledCircuit *F = circuit->exportCircuit();

  vector<osuCrypto::block> encsInputsA;
  vector<vector<CryptoPP::byte*>> circuitEncs = encs[gamma];
  string xBitString = Util::intToBitString(x, GV::n1);
  for(int j=0; j<GV::n1; j++) {
    int b = (int) xBitString[j] - 48;
    encsInputsA.push_back(Util::byteToBlock(circuitEncs.at(j).at(b), kappa));
  }

  cout << "A: sending F" << endl;
  chl.asyncSendCopy(F);
  cout << "A: sending my encoded input" << endl;
  chl.asyncSend(move(encsInputsA));

  //*************************************
  //TODO: commitments and decommitments
  //*************************************
  vector<osuCrypto::block> decommitmentsEncsInputsA;
  for(int j=0; j<GV::n1; j++) {
    pair<osuCrypto::block, osuCrypto::block> p = decommitmentsEncsA.at(j+(GV::n1*gamma));
    int b = (int) xBitString[j] - 48;
    osuCrypto::block decommit = (b) ? p.second : p.first;
    decommitmentsEncsInputsA.push_back(decommit);
  }

  cout << "A: sending decommits for my input encodings" << endl;
  chl.asyncSend(move(decommitmentsEncsInputsA));

  cout << "A: sending decommits for commits" << endl;
  chl.asyncSend(move(decommitmentsA));
  //*************************************
  //TODO: end
  //*************************************
  return true;
}

/*
  Garbling the circuits and prepare the ot data
*/
pair<vector<CircuitInterface*>, vector<array<osuCrypto::block, 2>>> PartyA::garbling(CircuitInterface* circuit, vector<CryptoPP::byte*> seedsA) {
  vector<CircuitInterface*> circuits;
  vector<array<osuCrypto::block, 2>> otData(lambda*GV::n2);

  for(int j=0; j<lambda; j++) {
    CircuitInterface *G = circuit->createInstance(kappa, seedsA.at(j));
    CircuitReader cr = CircuitReader();
    pair<bool, vector<vector<CryptoPP::byte*>>> import = cr.import(G, GV::filename);
    outputEncs[j] = cr.getOutputEnc();

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
      osuCrypto::block block0 = Util::byteToBlock(encsB.at(0), kappa);
      osuCrypto::block block1 = Util::byteToBlock(encsB.at(1), kappa);
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
void PartyA::otSeedsWitnesses(osuCrypto::KosOtExtSender* sender, osuCrypto::Channel serverChl, vector<CryptoPP::byte*> seedsA, vector<CryptoPP::byte*> witnesses, int length) {
  vector<array<osuCrypto::block, 2>> otData(lambda);
  for(int j=0; j<lambda; j++) {
    osuCrypto::block block0 = Util::byteToBlock(seedsA.at(j), kappa);
    osuCrypto::block block1 = Util::byteToBlock(witnesses.at(j), kappa);
    otData[j] = {block0, block1};
  }
  osuCrypto::PRNG prng(osuCrypto::sysRandomSeed()); //TODO: use own seed
  sender->sendChosen(otData, prng, serverChl);
}

/*
  Checks that party A has correct seeds and witness
*/
bool PartyA::checkSeedsWitness(vector<osuCrypto::block> gammaSeedsWitnessBlock, vector<CryptoPP::byte*> seedsA, vector<CryptoPP::byte*> witnesses) {
  int gamma = Util::byteToInt(Util::blockToByte(gammaSeedsWitnessBlock.at(0), 4));

  for(int j=0; j<lambda; j++) {
    CryptoPP::byte *b = Util::blockToByte(gammaSeedsWitnessBlock.at(j+1), kappa);
    if(lambda == j) {
      if(memcmp(witnesses.at(j), b, kappa) != 0) {
        cout << "A: Error! Witness is not correct" << endl;
        return false;
      }
    } else if(memcmp(seedsA.at(j), b, kappa) != 0 && j!=gamma) {
      cout << "A: Error! Seed is not correct" << endl;
      return false;
    }
  }
  return true;
}
