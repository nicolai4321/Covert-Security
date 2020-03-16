#include "PartyB.h"
using namespace std;

PartyB::PartyB(int input, int k, int l, osuCrypto::Channel c, CircuitInterface* cir, EvaluatorInterface* eI) {
  y = input;
  kappa = k;
  lambda = l;
  chl = c;
  circuit = cir;
  evaluator = eI;

  for(int j=0; j<lambda; j++) {
    iv[j] = 0;
  }

  CircuitReader cr = CircuitReader();
  pair<bool, vector<vector<CryptoPP::byte*>>> import = cr.import(circuit, GV::filename);
  if(import.first) {
    GarbledCircuit *F = circuit->exportCircuit();
    gateOrderB = F->getGateOrder();
    outputGatesB = F->getOutputGates();
    gateInfoB = F->getGateInfo();
  } else {
    cout << "B: Error! Invalid circuit file" << endl;
    throw;
  }
}

PartyB::~PartyB() {}

/*
  Starts the protocol
*/
bool PartyB::startProtocol() {
  gamma = Util::randomInt(0, lambda-1);

  //Generating random seeds
  vector<CryptoPP::byte*> seedsB;
  for(int i=0; i<lambda; i++) {
    seedsB.push_back(Util::randomByte(kappa));
  }

  //Commitments of the seeds for party B
  vector<osuCrypto::block> commitmentsB;
  for(int j=0; j<lambda; j++) {
    osuCrypto::block r = Util::byteToBlock(Util::randomByte(kappa, seedsB.at(j), iv[j]), kappa); iv[j] = iv[j]+1;
    CryptoPP::byte *c = Util::commit(Util::byteToBlock(seedsB.at(j), kappa), r);
    osuCrypto::block b = Util::byteToBlock(c, Util::COMMIT_LENGTH);
    commitmentsB.push_back(b);
  }

  cout << "B: sending my commitments" << endl;
  chl.asyncSend(move(commitmentsB));

  //First OT
  osuCrypto::KosOtExtReceiver recver;
  vector<osuCrypto::block> seedsWitnessA = otSeedsWitnessA(&recver, chl);
  cout << "B: has done first OT" << endl;

  //Second OT
  vector<osuCrypto::block> encsInputsGammaB = otEncodingsB(&recver, chl);
  cout << "B: has done second OT" << endl;

  //*************************************
  //TODO: check ot-communication and auth.
  //*************************************
    vector<osuCrypto::block> commitmentsEncsA;
    chl.recv(commitmentsEncsA);
    cout << "B: has received commitments for input encodings from other party" << endl;
    vector<osuCrypto::block> commitmentsCircuitsA;
    chl.recv(commitmentsCircuitsA);
    cout << "B: has received commitments for circuits from other party" << endl;
  //*************************************
  //TODO: end
  //*************************************

  //Sends gamma, witness and seeds to other party
  vector<osuCrypto::block> gammaSeedsWitnessBlock;
  gammaSeedsWitnessBlock.push_back(Util::byteToBlock(Util::intToByte(gamma), 4));
  for(int j=0; j<lambda; j++) {
    gammaSeedsWitnessBlock.push_back(seedsWitnessA.at(j));
  }
  cout << "B: sending witness, gamma and seeds" << endl;
  chl.asyncSend(move(gammaSeedsWitnessBlock));

  //Receive garbled circuit and input encodings from the other party
  GarbledCircuit *F;
  chl.recv(F);
  cout << "B: has received F" << endl;

  vector<osuCrypto::block> encsInputsA;
  chl.recv(encsInputsA);
  cout << "B: has received encodings from other party" << endl;

  vector<osuCrypto::block> decommitmentsEncA;
  chl.recv(decommitmentsEncA);
  cout << "B: has received decommits for input encodings" << endl;

  vector<osuCrypto::block> decommitmentsCircuitA;
  chl.recv(decommitmentsCircuitA);
  cout << "B: has received decommits" << endl;

  if(!checkCommitments(F, decommitmentsEncA, decommitmentsCircuitA, commitmentsEncsA, commitmentsCircuitsA, encsInputsA)) {return false;}

  return evaluate(F, encsInputsA, encsInputsGammaB);
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

/*

*/
bool PartyB::checkCommitments(GarbledCircuit* F, vector<osuCrypto::block> decommitmentsEncA, vector<osuCrypto::block> decommitmentsCircuitA, vector<osuCrypto::block> commitmentsEncsA, vector<osuCrypto::block> commitmentsCircuitsA, vector<osuCrypto::block> encsInputsA) {
  //Checking output encodings
  CryptoPP::byte *commit0 = PartyA::commitCircuit(kappa, circuit->getType(), F, decommitmentsCircuitA.at(gamma)); //correct commit
  CryptoPP::byte *commit1 = Util::blockToByte(commitmentsCircuitsA.at(gamma), Util::COMMIT_LENGTH); //commit from A

  if(memcmp(commit0, commit1, Util::COMMIT_LENGTH) != 0) {
    cout << "B: Error! Invalid circuit commitment from other party" << endl;
    return false;
  }

  //Checking input encodings
  for(int j=0; j<GV::n1; j++) {
    osuCrypto::block decommit = decommitmentsEncA.at(j);
    CryptoPP::byte* c = Util::commit(encsInputsA.at(j), decommit);
    CryptoPP::byte* c0 = Util::blockToByte(commitmentsEncsA.at(2*j+(2*GV::n1*gamma)), Util::COMMIT_LENGTH);
    CryptoPP::byte* c1 = Util::blockToByte(commitmentsEncsA.at(2*j+1+(2*GV::n1*gamma)), Util::COMMIT_LENGTH);

    if(memcmp(c, c0, Util::COMMIT_LENGTH) != 0 && memcmp(c, c1, Util::COMMIT_LENGTH) != 0) {
      cout << "B: Error! Invalid input encoding commitment from other party" << endl;
      return false;
    }
  }

  //Checking gate order
  vector<string> gateOrderA = F->getGateOrder();
  if(gateOrderA.size() != gateInfoB.size()) {
    cout << "B: Error! Not same amount of gates" << endl;
    return false;
  }
  for(int i=0; i<gateOrderA.size(); i++) {
    if(gateOrderA.at(i).compare(gateOrderB.at(i)) != 0) {
      cout << "B: Error! Gate order does not match" << endl;
      return false;
    }
  }

  //Checking output gates
  vector<string> outputGatesA = F->getOutputGates();
  if(outputGatesA.size() != outputGatesB.size()) {
    cout << "B: Error! Not same amount of output gates" << endl;
    return false;
  }
  for(int i=0; i<outputGatesA.size(); i++) {
    if(outputGatesA.at(i).compare(outputGatesB.at(i)) != 0) {
      cout << "B: Error! Output gates does not match" << endl;
      return false;
    }
  }

  //Checking gate info
  map<string, vector<string>> gateInfoA = F->getGateInfo();
  map<string, vector<string>>::iterator itA = gateInfoA.begin();
  map<string, vector<string>>::iterator itB = gateInfoB.begin();
  while(itA != gateInfoA.end() && itB != gateInfoB.end()) {
    string gateNameA = itA->first;
    vector<string> vA = gateInfoA[gateNameA];
    string gateTypeA = vA.at(0);
    string gateLA = vA.at(1);
    string gateRA = vA.at(2);

    string gateNameB = itB->first;
    vector<string> vB = gateInfoB[gateNameB];
    string gateTypeB = vB.at(0);
    string gateLB = vB.at(1);
    string gateRB = vB.at(2);

    if(gateTypeA.compare(gateTypeB) != 0 || gateLA.compare(gateLB) != 0 || gateRA.compare(gateRB) != 0) {
      cout << "B: Error! Gate info does not match" << endl;
      return false;
    }
    itA++;
    itB++;
  }
  if(itA != gateInfoA.end() || itB != gateInfoB.end()) {
    cout << "B: Error! Size of gate info does not match" << endl;
    return false;
  }

  return true;
}

/*
  Evaluates the circuit with the given input
*/
bool PartyB::evaluate(GarbledCircuit* F, vector<osuCrypto::block> encsInputsA, vector<osuCrypto::block> encsInputsGammaB) {
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
      cout << "B: Output,";
      for(bool b : output) {
        cout << b;
      }
      cout << endl;
      return true;
    } else {
      cout << "B: Error! Could not decode circuit" << endl;
      return false;
    }
  } else {
    cout << "B: Error! Could not evaluate circuit" << endl;
    return false;
  }
}
