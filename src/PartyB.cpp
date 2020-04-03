#include "PartyB.h"
using namespace std;

PartyB::PartyB(int input, CryptoPP::DSA::PublicKey publicKey, int k, int l, CircuitInterface* cir, EvaluatorInterface* eI) {
  y = input;
  pk = publicKey;
  kappa = k;
  lambda = l;
  circuit = cir;
  evaluator = eI;

  //Circuit reader
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
  //Network
  ios = new osuCrypto::IOService(16);
  chl = osuCrypto::Session(*ios, GV::ADDRESS, osuCrypto::SessionMode::Client).addChannel();
  osuCrypto::SocketInterface *socket= new SocketRecorder(chl);
  socketRecorder = (SocketRecorder*) socket;
  chlOT = osuCrypto::Channel(*ios, socket);

  //Gamma
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
  vector<osuCrypto::block> decommitmentsB;
  for(int j=0; j<lambda; j++) {
    osuCrypto::block r = Util::byteToBlock(Util::randomByte(kappa), kappa);
    CryptoPP::byte *c = Util::commit(Util::byteToBlock(seedsB.at(j), kappa), r);
    osuCrypto::block b = Util::byteToBlock(c, Util::COMMIT_LENGTH);
    commitmentsB.push_back(b);
    commitmentsBSend.push_back(b);
    decommitmentsB.push_back(r);
  }

  cout << "B: sending my commitments" << endl;
  chl.waitForConnection();
  chl.asyncSend(move(commitmentsBSend));

  //First OT
  osuCrypto::KosOtExtReceiver recver;
  chlOT.waitForConnection();
  vector<osuCrypto::block> seedsWitnessA = otSeedsWitnessA(&recver, chlOT, socketRecorder, seedsB, &ivB);
  cout << "B: has done first OT" << endl;

  //Second OT
  vector<osuCrypto::block> encsInputsB = otEncodingsB(&recver, y, lambda, kappa, gamma, chlOT, socketRecorder, seedsB, &ivB);
  cout << "B: has done second OT" << endl;

  //Receive commitments
  vector<osuCrypto::block> commitmentsEncsA;
  chl.recv(commitmentsEncsA);
  cout << "B: has received commitments for input encodings from other party" << endl;
  vector<osuCrypto::block> commitmentsCircuitsA;
  chl.recv(commitmentsCircuitsA);
  cout << "B: has received commitments for circuits from other party" << endl;

  //Receive signatures
  vector<SignatureHolder*> signatureHolders;
  chl.recv(signatureHolders);
  cout << "B: has received signatures" << endl;

  //Simulate party A to check signatures and commitments
  if(!simulatePartyA(&recver, seedsB, signatureHolders, seedsWitnessA, commitmentsEncsA, commitmentsCircuitsA, commitmentsB, decommitmentsB)) {
    chlOT.close();
    chl.close();
    ios->stop();
    return false;
  }

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

  if(!checkCommitments(F, decommitmentsEncA, decommitmentsCircuitA, commitmentsEncsA, commitmentsCircuitsA, encsInputsA)) {
    chlOT.close();
    chl.close();
    ios->stop();
    return false;
  }

  chlOT.close();
  chl.close();
  ios->stop();
  return evaluate(F, encsInputsA, encsInputsB);
}

/*
  First OT-interaction. Receives seeds and witnesses for A
*/
vector<osuCrypto::block> PartyB::otSeedsWitnessA(osuCrypto::KosOtExtReceiver* recver, osuCrypto::Channel channel, SocketRecorder *sRecorder, vector<CryptoPP::byte*> seedsB,
                                                 map<unsigned int, unsigned int>* ivB) {
  vector<osuCrypto::block> seedsWitnessA;
  sRecorder->forceStore("ot1", lambda, 12, 68);
  for(int j=0; j<lambda; j++) {
    osuCrypto::BitVector b(1);
    b[0] = (j==gamma) ? 1 : 0;

    CryptoPP::byte *seedInput = Util::randomByte(kappa, seedsB.at(j), kappa, (*ivB)[j]); (*ivB)[j] = (*ivB)[j]+1;
    osuCrypto::PRNG prng(Util::byteToBlock(seedInput, kappa));
    vector<osuCrypto::block> dest(1);
    recver->genBaseOts(prng, channel);
    recver->receiveChosen(b, dest, prng, channel);
    seedsWitnessA.push_back(dest[0]);
  }
  return seedsWitnessA;
}

/*
  Second OT-interaction. Receives encodings for own input
*/
vector<osuCrypto::block> PartyB::otEncodingsB(osuCrypto::KosOtExtReceiver* recver, int input, int lambd, int kapp, int gamm, osuCrypto::Channel channel,
                                              SocketRecorder *sRecorder, vector<CryptoPP::byte*> seedsB, map<unsigned int, unsigned int>* ivB) {
  string yString = Util::intToBitString(input, GV::n2);

  vector<osuCrypto::block> encsB;
  sRecorder->forceStore("ot2", lambd, 12, 68);
  for(int j=0; j<lambd; j++) {
    osuCrypto::BitVector b(GV::n2);
    for(int i=0; i<GV::n2; i++) {
      if(j == gamm) {
        b[i] = (int) yString[i] - 48;
      } else {
        b[i] = 0;
      }
    }

    vector<osuCrypto::block> encs(GV::n2);
    CryptoPP::byte* seed = seedsB.at(j);
    CryptoPP::byte* seedInput = Util::randomByte(kapp, seed, kapp, (*ivB)[j]); (*ivB)[j] = (*ivB)[j]+1;
    osuCrypto::PRNG prng(Util::byteToBlock(seedInput, kapp));
    recver->genBaseOts(prng, channel);
    recver->receiveChosen(b, encs, prng, channel);

    if(j==gamm) {
      for(int i=0; i<GV::n2; i++) {
        encsB.push_back(encs[i]);
      }
    }
  }

  return encsB;
}

/*
  This function checks the commitments for the lambda circuit
*/
bool PartyB::checkCommitments(GarbledCircuit* F, vector<osuCrypto::block> decommitmentsEncA, vector<osuCrypto::block> decommitmentsCircuitA,
                              vector<osuCrypto::block> commitmentsEncsA, vector<osuCrypto::block> commitmentsCircuitsA, vector<osuCrypto::block> encsInputsA) {
  CryptoPP::byte *commitSim = PartyA::commitCircuit(kappa, circuit->getType(), F, decommitmentsCircuitA.at(gamma));
  CryptoPP::byte *commit = Util::blockToByte(commitmentsCircuitsA.at(gamma), Util::COMMIT_LENGTH);

  if(memcmp(commitSim, commit, Util::COMMIT_LENGTH) != 0) {
    cout << "B: Error! Invalid circuit commitment from other party" << endl;
    return false;
  }

  //Checking input encodings
  int startIndex = 2*gamma*GV::n1;
  for(int i=0; i<GV::n1; i++) {
    osuCrypto::block decommit = decommitmentsEncA.at(i);
    CryptoPP::byte* c = Util::commit(encsInputsA.at(i), decommit);
    CryptoPP::byte* c0 = Util::blockToByte(commitmentsEncsA.at(startIndex+2*i), Util::COMMIT_LENGTH);
    CryptoPP::byte* c1 = Util::blockToByte(commitmentsEncsA.at(startIndex+2*i+1), Util::COMMIT_LENGTH);

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
bool PartyB::simulatePartyA(osuCrypto::KosOtExtReceiver* recver, vector<CryptoPP::byte*> seedsB, vector<SignatureHolder*> signatureHolders,
                            vector<osuCrypto::block> seedsWitnessA, vector<osuCrypto::block> commitmentsEncsA,
                            vector<osuCrypto::block> commitmentsCircuitsA, vector<osuCrypto::block> commitmentsB,
                            vector<osuCrypto::block> decommitmentsB) {
  //Checking signatures
  cout << "B: checking signatures" << endl;
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
  cout << "B: generating seeds" << endl;
  map<unsigned int, unsigned int> ivAsim;
  map<unsigned int, unsigned int> ivBSim;
  vector<CryptoPP::byte*> seedsA;
  for(int j=0; j<lambda; j++) {
    seedsA.push_back(Util::blockToByte(seedsWitnessA.at(j), kappa));
    ivAsim[j] = 1;
    ivBSim[j] = 1;
  }

  //Simulated garbling
  cout << "B: simulating garbling" << endl;
  pair<vector<CircuitInterface*>, map<int, vector<vector<CryptoPP::byte*>>>> garblingInfo = PartyA::garbling(lambda, kappa, circuit, seedsA);
  vector<CircuitInterface*> circuits = garblingInfo.first;
  map<int, vector<vector<CryptoPP::byte*>>> encsSimulated = garblingInfo.second;

  //Network
  osuCrypto::Channel chlSerSim = osuCrypto::Session(*ios, GV::ADDRESS_SIM, osuCrypto::SessionMode::Server).addChannel();
  osuCrypto::Channel chlCliSim = osuCrypto::Session(*ios, GV::ADDRESS_SIM, osuCrypto::SessionMode::Client).addChannel();
  osuCrypto::SocketInterface *siSerSim = new SocketRecorder(chlSerSim);
  osuCrypto::SocketInterface *siCliSim = new SocketRecorder(chlCliSim);
  SocketRecorder *socSerSim = (SocketRecorder*) siSerSim;
  SocketRecorder *socCliSim = (SocketRecorder*) siCliSim;
  osuCrypto::Channel recSerSim(*ios, siSerSim);
  osuCrypto::Channel recCliSim(*ios, siCliSim);
  chlCliSim.waitForConnection();
  recCliSim.waitForConnection();

  //Simulating the 2nd OT
  auto senderThread = thread([&]() {
  osuCrypto::KosOtExtSender sender;
    PartyA::otEncs(&sender, lambda, kappa, recSerSim, socSerSim, encsSimulated, seedsA, &ivAsim);
  });
  otEncodingsB(recver, y, lambda, kappa, gamma, recCliSim, socCliSim, seedsB, &ivBSim);
  senderThread.join();

  //Checking the conent of the transscripts
  cout << "B: checking transscripts" << endl;
  for(int j=0; j<lambda; j++) {
    if(j != gamma) {
      SignatureHolder* signatureHolder = signatureHolders.at(j);
      string msg = signatureHolder->getMsg();

      vector<osuCrypto::block> commitmentsEncsAJ;
      int startIndex = 2*j*GV::n1;
      for(int i=0; i<GV::n1; i++) {
        commitmentsEncsAJ.push_back(commitmentsEncsA.at(startIndex+2*i));
        commitmentsEncsAJ.push_back(commitmentsEncsA.at(startIndex+2*i+1));
      }
      string msgSim = PartyA::constructSignatureString(j, kappa, commitmentsCircuitsA.at(j), commitmentsB.at(j), commitmentsEncsAJ,
                                                       socketRecorder->getRecvCat("ot1"+to_string(j)),
                                                       socketRecorder->getSentCat("ot1"+to_string(j)),
                                                       socSerSim->getSentCat("ot2"+to_string(j)),
                                                       socSerSim->getRecvCat("ot2"+to_string(j)));

      if(msg.compare(msgSim) != 0) {
        cout << "B: signature of invalid data for round: " << j << endl;
        socSerSim->close();
        socCliSim->close();
        recSerSim.close();
        recCliSim.close();
        chlSerSim.close();
        chlCliSim.close();
        return false;
      }
    }
  }

  //Checking commitments
  pair<vector<osuCrypto::block>, vector<pair<osuCrypto::block, osuCrypto::block>>> commitPairSimulated =
    PartyA::commitEncsA(lambda, kappa, seedsA, &ivAsim, encsSimulated);
  vector<osuCrypto::block> commitmentsEncsASimulated = commitPairSimulated.first;

  pair<vector<osuCrypto::block>, vector<osuCrypto::block>> commitPair = PartyA::commitCircuits(lambda, kappa, circuit, seedsA, &ivAsim, circuits);
  vector<osuCrypto::block> commitmentsA = commitPair.first;
  vector<osuCrypto::block> decommitmentsA = commitPair.second;

  bool callJudge = false;
  int j;
  for(j=0; j<lambda; j++) {
    if(j != gamma) {
      int startIndex = 2*j*GV::n1;
      for(int i=0; i<GV::n1; i++) {
        CryptoPP::byte *commitSimulated0 = Util::blockToByte(commitmentsEncsASimulated.at(startIndex+2*i), Util::COMMIT_LENGTH);
        CryptoPP::byte *commitReceived0 = Util::blockToByte(commitmentsEncsA.at(startIndex+2*i), Util::COMMIT_LENGTH);
        CryptoPP::byte *commitSimulated1 = Util::blockToByte(commitmentsEncsASimulated.at(startIndex+2*i+1), Util::COMMIT_LENGTH);
        CryptoPP::byte *commitReceived1 = Util::blockToByte(commitmentsEncsA.at(startIndex+2*i+1), Util::COMMIT_LENGTH);
        if(memcmp(commitSimulated0, commitReceived0, Util::COMMIT_LENGTH) != 0 ||
           memcmp(commitSimulated1, commitReceived1, Util::COMMIT_LENGTH) != 0) {
          cout << "B: Corrupt! Simulation of commitments for input encodings does not match" << endl;
          callJudge = true;
          goto skip;
        }
      }

      CryptoPP::byte *commitSimulated1 = Util::blockToByte(commitmentsA.at(j), Util::COMMIT_LENGTH);
      CryptoPP::byte *commitReceived1 = Util::blockToByte(commitmentsCircuitsA.at(j), Util::COMMIT_LENGTH);

      if(memcmp(commitSimulated1, commitReceived1, Util::COMMIT_LENGTH) != 0) {
        cout << "B: Corrupt! Simulation of commitments for circuits does not match" << endl;
        callJudge = true;
        goto skip;
      }
    }
  }
  skip:

  if(callJudge) {
    cout << "B: calling judge" << endl;
    vector<osuCrypto::block> commitmentsEncsAJ;
    int startIndex = 2*j*GV::n1;
    for(int i=0; i<GV::n1; i++) {
      commitmentsEncsAJ.push_back(commitmentsEncsA.at(startIndex+2*i));
      commitmentsEncsAJ.push_back(commitmentsEncsA.at(startIndex+2*i+1));
    }

    SignatureHolder* signatureHolder = signatureHolders.at(j);
    string signature = signatureHolder->getSignature();

    Judge judge(kappa, pk, circuit);
    bool judgement = judge.accuse(j, signature, seedsB.at(j), decommitmentsB.at(j), commitmentsA.at(j), commitmentsEncsAJ,
                                  socketRecorder->getRecvCat("ot1"+to_string(j)),
                                  socketRecorder->getSentCat("ot1"+to_string(j)),
                                  socSerSim->getSentCat("ot2"+to_string(j)),
                                  socSerSim->getRecvCat("ot2"+to_string(j)));

    cout << "B: the judgement is: " << judgement << endl;

    socSerSim->close();
    socCliSim->close();
    recSerSim.close();
    recCliSim.close();
    chlSerSim.close();
    chlCliSim.close();

    return false;
  }

  socSerSim->close();
  socCliSim->close();
  recSerSim.close();
  recCliSim.close();
  chlSerSim.close();
  chlCliSim.close();
  return true;
}
