#include "PartyB.h"
using namespace std;

PartyB::PartyB(int input, CryptoPP::DSA::PublicKey publicKey, int k, int l, osuCrypto::Channel c, SocketRecorder *sr, CircuitInterface* cir, EvaluatorInterface* eI) {
  y = input;
  pk = publicKey;
  kappa = k;
  lambda = l;
  chlOT = c;
  chl = sr->getMChl();
  socketRecorder = sr;
  circuit = cir;
  evaluator = eI;

  CircuitReader cr = CircuitReader();
  pair<bool, vector<vector<CryptoPP::byte*>>> import = cr.import(circuit, GV::filename);
  if(import.first) {
    GarbledCircuit *F = circuit->exportCircuit();
    gateOrderB = F->getGateOrder();
    outputGatesB = F->getOutputGates();
    gateInfoB = F->getGateInfo();
  } else {
    throw runtime_error("B: Error! Invalid circuit file");
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
  map<unsigned int, unsigned int> ivB;
  for(int j=0; j<lambda; j++) {
    seedsB.push_back(Util::randomByte(kappa));
    ivB[j] = 0;
  }

  //Commitments of the seeds for party B
  vector<osuCrypto::block> commitmentsBSend;
  vector<osuCrypto::block> commitmentsB;
  for(int j=0; j<lambda; j++) {
    osuCrypto::block r = Util::byteToBlock(Util::randomByte(kappa, seedsB.at(j), ivB[j]), kappa); ivB[j] = ivB[j]+1;
    CryptoPP::byte *c = Util::commit(Util::byteToBlock(seedsB.at(j), kappa), r);
    osuCrypto::block b = Util::byteToBlock(c, Util::COMMIT_LENGTH);
    commitmentsB.push_back(b);
    commitmentsBSend.push_back(b);
  }

  cout << "B: sending my commitments" << endl;
  chl.asyncSend(move(commitmentsBSend));

  //First OT
  osuCrypto::KosOtExtReceiver recver;
  vector<osuCrypto::block> seedsWitnessA = otSeedsWitnessA(&recver, chlOT, seedsB, &ivB);
  cout << "B: has done first OT" << endl;

  //Second OT
  vector<osuCrypto::block> encsInputsB = otEncodingsB(y, lambda, kappa, gamma, &recver, chlOT, socketRecorder, seedsB, &ivB, &transcriptsSent1, &transcriptsRecv1);
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

    vector<SignatureHolder*> signatureHolders;
    chl.recv(signatureHolders);
    cout << "B: has received signatures" << endl;

    if(!simulatePartyA(seedsB, signatureHolders, seedsWitnessA, commitmentsEncsA, commitmentsCircuitsA, commitmentsB)) {return false;}

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

  return evaluate(F, encsInputsA, encsInputsB);
}

/*
  First OT-interaction. Receives seeds and witnesses for A
*/
vector<osuCrypto::block> PartyB::otSeedsWitnessA(osuCrypto::KosOtExtReceiver* recver, osuCrypto::Channel chlOT, vector<CryptoPP::byte*> seedsB, map<unsigned int, unsigned int>* ivB) {
  vector<osuCrypto::block> seedsWitnessA;
  for(int j=0; j<lambda; j++) {
    socketRecorder->clearDataRecv();
    socketRecorder->clearDataSent();

    osuCrypto::BitVector b(1);
    b[0] = (j==gamma) ? 1 : 0;

    CryptoPP::byte *seedInput = Util::randomByte(kappa, seedsB.at(j), (*ivB)[j]); (*ivB)[j] = (*ivB)[j]+1;
    osuCrypto::PRNG prng(Util::byteToBlock(seedInput, 16), 16);
    vector<osuCrypto::block> dest(1);
    recver->receiveChosen(b, dest, prng, chlOT);
    seedsWitnessA.push_back(dest[0]);

    transcriptsRecv0.push_back(socketRecorder->getDataRecv());
    transcriptsSent0.push_back(socketRecorder->getDataSent());
  }
  return seedsWitnessA;
}

/*
  Second OT-interaction. Receives encodings for own input
*/
vector<osuCrypto::block> PartyB::otEncodingsB(int input, int lambd, int kapp, int gamm, osuCrypto::KosOtExtReceiver *recver, osuCrypto::Channel chlOT, SocketRecorder *socketR, vector<CryptoPP::byte*> seedsB, map<unsigned int, unsigned int>* ivB, vector<vector<pair<int, unsigned char*>>>* transcriptsSent, vector<vector<pair<int, unsigned char*>>>* transcriptsRecv) {
  string yString = Util::intToBitString(input, GV::n2);
  vector<osuCrypto::block> encsB;
  for(int j=0; j<lambd; j++) {
    socketR->clearDataSent();
    socketR->clearDataRecv();
    osuCrypto::BitVector b(GV::n2);

    for(int i=0; i<GV::n2; i++) {
      if(j == gamm) {
        b[i] = (int) yString[i] - 48;
      } else {
        b[i] = 0;
      }
    }

    vector<osuCrypto::block> encs(GV::n2);
    CryptoPP::byte* seedInput = Util::randomByte(kapp, seedsB.at(j), (*ivB)[j]); (*ivB)[j] = (*ivB)[j]+1;
    osuCrypto::PRNG prng(Util::byteToBlock(seedInput, kapp), kapp);
    recver->receiveChosen(b, encs, prng, chlOT);
    if(j==gamm) {
      for(int i=0; i<GV::n1; i++) {
        encsB.push_back(encs[i]);
      }
    }

    transcriptsSent->push_back(socketR->getDataSent());
    transcriptsRecv->push_back(socketR->getDataRecv());
  }

  return encsB;
}

/*
  This function checks the commitments for the lambda circuit
*/
bool PartyB::checkCommitments(GarbledCircuit* F, vector<osuCrypto::block> decommitmentsEncA, vector<osuCrypto::block> decommitmentsCircuitA, vector<osuCrypto::block> commitmentsEncsA, vector<osuCrypto::block> commitmentsCircuitsA, vector<osuCrypto::block> encsInputsA) {
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
bool PartyB::evaluate(GarbledCircuit* F, vector<osuCrypto::block> encsInputsA, vector<osuCrypto::block> encsInputsB) {
  vector<CryptoPP::byte*> encsInputs;
  for(int j=0; j<GV::n1; j++) {
    encsInputs.push_back(Util::blockToByte(encsInputsA.at(j), kappa));
  }
  for(int j=0; j<GV::n2; j++) {
    encsInputs.push_back(Util::blockToByte(encsInputsB.at(j), kappa));
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

/*
  Checks that the input encodings is computed from the seed
*/
bool PartyB::simulatePartyA(vector<CryptoPP::byte*> seedsB, vector<SignatureHolder*> signatureHolders, vector<osuCrypto::block> seedsWitnessA, vector<osuCrypto::block> commitmentsEncsA, vector<osuCrypto::block> commitmentsCircuitsA, vector<osuCrypto::block> commitmentsB) {

  //Checking signatures
  for(int j=0; j<lambda; j++) {
    SignatureHolder* signatureHolder = signatureHolders.at(j);
    string msg = signatureHolder->getMsg();
    string signature = signatureHolder->getSignature();
    if(!Signature::verify(pk, signature, msg)) {
      cout << "B: found invalid signature" << endl;
      return false;
    }
  }

  //Generating seeds
  map<unsigned int, unsigned int> ivA;
  map<unsigned int, unsigned int> ivBSim;
  vector<CryptoPP::byte*> seedsA;
  for(int j=0; j<lambda; j++) {
    seedsA.push_back(Util::blockToByte(seedsWitnessA.at(j), kappa));
    ivA[j] = 1;
    ivBSim[j] = 2;
  }

  pair<vector<CircuitInterface*>, map<int, vector<vector<CryptoPP::byte*>>>> garblingInfo = PartyA::garbling(lambda, kappa, circuit, seedsA);
  vector<CircuitInterface*> circuits = garblingInfo.first;
  map<int, vector<vector<CryptoPP::byte*>>> encsSimulated = garblingInfo.second;

  //Simulating the 2nd OT
  osuCrypto::IOService iosSim(16);
  osuCrypto::Channel chlSerSim = osuCrypto::Session(iosSim, GV::ADDRESS_SIM, osuCrypto::SessionMode::Server).addChannel();
  osuCrypto::Channel chlCliSim = osuCrypto::Session(iosSim, GV::ADDRESS_SIM, osuCrypto::SessionMode::Client).addChannel();
  osuCrypto::SocketInterface *siSerRecSim = new SocketRecorder(chlSerSim);
  osuCrypto::SocketInterface *siCliRecsim = new SocketRecorder(chlCliSim);
  SocketRecorder *socketRecorderServer = (SocketRecorder*) siSerRecSim;
  SocketRecorder *socketRecorderClient = (SocketRecorder*) siCliRecsim;
  Channel serSim(iosSim, siSerRecSim);
  Channel cliSim(iosSim, siCliRecsim);
  osuCrypto::KosOtExtSender sender;
  osuCrypto::KosOtExtReceiver recver;

  vector<vector<pair<int, unsigned char*>>> tMySent0;
  vector<vector<pair<int, unsigned char*>>> tMyRecv0;
  vector<vector<pair<int, unsigned char*>>> tSentSim1;
  vector<vector<pair<int, unsigned char*>>> tRecvSim1;
  chlCliSim.waitForConnection();
  cliSim.waitForConnection();

  //RECEIVER
  auto recverThread = thread([&]() {
    otEncodingsB(y, lambda, kappa, gamma, &recver, cliSim, socketRecorderClient, seedsB, &ivBSim, &tMySent0, &tMyRecv0);
  });

  //SENDER
  auto senderThread = thread([&]() {
    socketRecorderServer->clearDataRecv();
    socketRecorderServer->clearDataSent();
    PartyA::otEncs(lambda, kappa, &sender, serSim, socketRecorderServer, encsSimulated, seedsA, &ivA, &tSentSim1, &tRecvSim1);
  });

  recverThread.join();
  senderThread.join();
  siCliRecsim->close();
  siSerRecSim->close();
  cliSim.close();
  serSim.close();
  chlCliSim.close();
  chlSerSim.close();
  iosSim.stop();

  for(int j=0; j<lambda; j++) {
    if(j != gamma) {
      SignatureHolder* signatureHolder = signatureHolders.at(j);
      string msg = signatureHolder->getMsg();
      string msgSim = PartyA::constructSignatureString(j, kappa, commitmentsCircuitsA, commitmentsB, commitmentsEncsA, false, tSentSim1, tRecvSim1, tSentSim1, tRecvSim1);

      if((msg.substr(0, msgSim.size())).compare(msgSim) != 0) {
        cout << "B: signature of invalid data for round: " << j << endl;

        return false;
      }
    }
  }

  pair<vector<osuCrypto::block>, vector<pair<osuCrypto::block, osuCrypto::block>>> commitPairSimulated = PartyA::commitEncsA(lambda, kappa, seedsA, &ivA, encsSimulated);
  vector<osuCrypto::block> commitmentsEncsASimulated = commitPairSimulated.first;

  pair<vector<osuCrypto::block>, vector<osuCrypto::block>> commitPair = PartyA::commitCircuits(lambda, kappa, circuit, seedsA, &ivA, circuits);
  vector<osuCrypto::block> commitmentsA = commitPair.first;
  vector<osuCrypto::block> decommitmentsA = commitPair.second;

  for(int j=0; j<lambda; j++) {
    if(j!=gamma) {
      for(int i=0; i<2*GV::n1; i++) {
        int index = i+(j*2*GV::n1);
        CryptoPP::byte *commitSimulated0 = Util::blockToByte(commitmentsEncsASimulated.at(index), Util::COMMIT_LENGTH);
        CryptoPP::byte *commitReceived0 = Util::blockToByte(commitmentsEncsA.at(index), Util::COMMIT_LENGTH);
        if(memcmp(commitSimulated0, commitReceived0, Util::COMMIT_LENGTH) != 0) {
          cout << "Corrupt! Simulation of commitments for input encodings does not match" << endl;
          //TODO: send to judge
          return false;
        }
      }

      CryptoPP::byte *commitSimulated1 = Util::blockToByte(commitmentsA.at(j), Util::COMMIT_LENGTH);
      CryptoPP::byte *commitReceived1 = Util::blockToByte(commitmentsCircuitsA.at(j), Util::COMMIT_LENGTH);

      if(memcmp(commitSimulated1, commitReceived1, Util::COMMIT_LENGTH) != 0) {
          cout << "Corrupt! Simulation of commitments for circuits does not match" << endl;
          //TODO: send to judge
          return false;
      }
    }
  }

  return true;
}
