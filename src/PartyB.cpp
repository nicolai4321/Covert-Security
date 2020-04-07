#include "PartyB.h"
using namespace std;

PartyB::PartyB(int input, CryptoPP::ESIGN<CryptoPP::Whirlpool>::PublicKey publicKey, int k, int l, CircuitInterface* cir, EvaluatorInterface* eI, TimeLog *timelog) {
  y = input;
  pk = publicKey;
  kappa = k;
  lambda = l;
  circuit = cir;
  evaluator = eI;
  timeLog = timelog;

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
  timeLog->markTime("network setup");
  ios = new osuCrypto::IOService(16);
  chl = osuCrypto::Session(*ios, GV::ADDRESS, osuCrypto::SessionMode::Client).addChannel();
  osuCrypto::SocketInterface *socket= new SocketRecorder(chl);
  socketRecorder = (SocketRecorder*) socket;
  chlOT = osuCrypto::Channel(*ios, socket);
  timeLog->endMark("network setup");

  //Gamma
  timeLog->markTime("generate gamma, seeds");
  gamma = Util::randomInt(0, lambda-1);

  //Generating random seeds
  vector<CryptoPP::byte*> seedsB;
  map<unsigned int, unsigned int> ivB;
  for(int j=0; j<lambda; j++) {
    seedsB.push_back(Util::randomByte(kappa));
    ivB[j] = 0;
  }
  timeLog->endMark("generate gamma, seeds");

  //Commitments of the seeds for party B
  timeLog->markTime("generate commitments of own seed");
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
  timeLog->endMark("generate commitments of own seed");

  timeLog->markTime("sending seeds");
  if(GV::PRINT_NETWORK_COMMUNICATION) cout << "B: sending my commitments" << endl;
  chl.waitForConnection();
  chl.asyncSend(move(commitmentsBSend));
  timeLog->endMark("sending seeds");

  //First OT
  timeLog->markTime("1st ot");
  osuCrypto::KosOtExtReceiver recver;
  chlOT.waitForConnection();
  vector<osuCrypto::block> seedsWitnessA = otSeedsWitnessA(&recver, chlOT, socketRecorder, seedsB, &ivB);
  if(GV::PRINT_NETWORK_COMMUNICATION) cout << "B: has done first OT" << endl;
  timeLog->endMark("1st ot");

  //Second OT
  timeLog->markTime("2nd ot");
  vector<osuCrypto::block> encsInputsB = otEncodingsB(&recver, y, lambda, kappa, gamma, chlOT, socketRecorder, seedsB, &ivB);
  if(GV::PRINT_NETWORK_COMMUNICATION) cout << "B: has done second OT" << endl;
  timeLog->endMark("2nd ot");

  //Receive commitments
  timeLog->markTime("waiting for commitments");
  vector<osuCrypto::block> commitmentsEncsA;
  chl.recv(commitmentsEncsA);
  if(GV::PRINT_NETWORK_COMMUNICATION) cout << "B: has received commitments for input encodings from other party" << endl;
  vector<osuCrypto::block> commitmentsCircuitsA;
  chl.recv(commitmentsCircuitsA);
  if(GV::PRINT_NETWORK_COMMUNICATION) cout << "B: has received commitments for circuits from other party" << endl;
  timeLog->endMark("waiting for commitments");

  //Receive signatures
  timeLog->markTime("waiting for signatures");
  vector<SignatureHolder*> signatureHolders;
  chl.recv(signatureHolders);
  if(GV::PRINT_NETWORK_COMMUNICATION) cout << "B: has received signatures" << endl;
  timeLog->endMark("waiting for signatures");

  //Simulate party A to check signatures and commitments
  timeLog->markTime("simulate");
  if(!simulatePartyA(&recver, seedsB, signatureHolders, seedsWitnessA, commitmentsEncsA, commitmentsCircuitsA, commitmentsB, decommitmentsB)) {
    chlOT.close();
    chl.close();
    ios->stop();
    return false;
  }
  timeLog->endMark("simulate");

  //Sends gamma, witness and seeds to other party
  timeLog->markTime("send gamma seed witness");
  vector<osuCrypto::block> gammaSeedsWitnessBlock;
  gammaSeedsWitnessBlock.push_back(Util::byteToBlock(Util::intToByte(gamma), 4));
  for(int j=0; j<lambda; j++) {
    gammaSeedsWitnessBlock.push_back(seedsWitnessA.at(j));
  }
  if(GV::PRINT_NETWORK_COMMUNICATION) cout << "B: sending witness, gamma and seeds" << endl;
  chl.asyncSend(move(gammaSeedsWitnessBlock));
  timeLog->endMark("send gamma seed witness");

  //Receive garbled circuit and input encodings from the other party
  timeLog->markTime("waiting for circuit and decommits");
  GarbledCircuit *F;
  chl.recv(F);
  if(GV::PRINT_NETWORK_COMMUNICATION) cout << "B: has received F" << endl;

  vector<osuCrypto::block> encsInputsA;
  chl.recv(encsInputsA);
  if(GV::PRINT_NETWORK_COMMUNICATION) cout << "B: has received encodings from other party" << endl;

  vector<osuCrypto::block> decommitmentsEncA;
  chl.recv(decommitmentsEncA);
  if(GV::PRINT_NETWORK_COMMUNICATION) cout << "B: has received decommits for input encodings" << endl;

  vector<osuCrypto::block> decommitmentsCircuitA;
  chl.recv(decommitmentsCircuitA);
  if(GV::PRINT_NETWORK_COMMUNICATION) cout << "B: has received decommits" << endl;
  timeLog->endMark("waiting for circuit and decommits");

  timeLog->markTime("checking commits");
  if(!checkCommitments(F, decommitmentsEncA, decommitmentsCircuitA, commitmentsEncsA, commitmentsCircuitsA, encsInputsA)) {
    chlOT.close();
    chl.close();
    ios->stop();
    return false;
  }
  timeLog->endMark("checking commits");

  chlOT.close();
  chl.close();
  ios->stop();

  timeLog->markTime("evaluate");
  bool output = evaluate(F, encsInputsA, encsInputsB);
  timeLog->endMark("evaluate");
  return output;
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
  timeLog->markTime("  check signatures");
  if(GV::PRINT_NETWORK_COMMUNICATION) cout << "B: checking signatures" << endl;
  for(int j=0; j<lambda; j++) {
    SignatureHolder* signatureHolder = signatureHolders.at(j);
    if(!Signature::verify(pk, signatureHolder)) {
      cout << "B: found invalid signature" << endl;
      return false;
    }
  }
  timeLog->endMark("  check signatures");

  //Generating seeds
  timeLog->markTime("  seeds");
  if(GV::PRINT_NETWORK_COMMUNICATION) cout << "B: generating seeds" << endl;
  map<unsigned int, unsigned int> ivAsim;
  map<unsigned int, unsigned int> ivBSim;
  vector<CryptoPP::byte*> seedsA;
  for(int j=0; j<lambda; j++) {
    seedsA.push_back(Util::blockToByte(seedsWitnessA.at(j), kappa));
    ivAsim[j] = 1;
    ivBSim[j] = 1;
  }
  timeLog->endMark("  seeds");

  //Simulated garbling
  timeLog->markTime("  garbling");
  if(GV::PRINT_NETWORK_COMMUNICATION) cout << "B: simulating garbling" << endl;
  pair<vector<CircuitInterface*>, map<int, vector<vector<CryptoPP::byte*>>>> garblingInfo = PartyA::garbling(lambda, kappa, circuit, seedsA);
  vector<CircuitInterface*> circuits = garblingInfo.first;
  map<int, vector<vector<CryptoPP::byte*>>> encsSimulated = garblingInfo.second;
  timeLog->endMark("  garbling");

  //Network
  timeLog->markTime("  network setup");
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
  timeLog->endMark("  network setup");

  //Simulating the 2nd OT
  timeLog->markTime("  2nd ot");
  auto senderThread = thread([&]() {
  osuCrypto::KosOtExtSender sender;
    PartyA::otEncs(&sender, lambda, kappa, recSerSim, socSerSim, encsSimulated, seedsA, &ivAsim);
  });
  otEncodingsB(recver, y, lambda, kappa, gamma, recCliSim, socCliSim, seedsB, &ivBSim);
  senderThread.join();
  timeLog->endMark("  2nd ot");

  //Checking the conent of the transscripts
  timeLog->markTime("  check transscripts");
  if(GV::PRINT_NETWORK_COMMUNICATION) cout << "B: checking transscripts" << endl;
  for(int j=0; j<lambda; j++) {
    if(j != gamma) {
      timeLog->markTime("    get msg"+to_string(j));
      SignatureHolder *signatureHolder = signatureHolders.at(j);
      CryptoPP::byte *msg = signatureHolder->getMsg();
      timeLog->endMark("    get msg"+to_string(j));

      timeLog->markTime("    find commitments for encs"+to_string(j));
      vector<osuCrypto::block> commitmentsEncsAJ;
      int startIndex = 2*j*GV::n1;
      for(int i=0; i<GV::n1; i++) {
        commitmentsEncsAJ.push_back(commitmentsEncsA.at(startIndex+2*i));
        commitmentsEncsAJ.push_back(commitmentsEncsA.at(startIndex+2*i+1));
      }
      timeLog->endMark("    find commitments for encs"+to_string(j));

      timeLog->markTime("    construct signature string"+to_string(j));
      pair<CryptoPP::byte*,int> msgSim = PartyA::constructSignatureByte(j, kappa, &commitmentsCircuitsA.at(j), &commitmentsB.at(j), &commitmentsEncsAJ,
                                                                         socketRecorder->getRecvCat("ot1"+to_string(j)),
                                                                         socketRecorder->getSentCat("ot1"+to_string(j)),
                                                                         socSerSim->getSentCat("ot2"+to_string(j)),
                                                                         socSerSim->getRecvCat("ot2"+to_string(j)));
      timeLog->endMark("    construct signature string"+to_string(j));

      if(memcmp(msg, msgSim.first, msgSim.second) != 0) {
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
  timeLog->endMark("  check transscripts");

  //Checking commitments
  timeLog->markTime("  commitments encs");
  pair<vector<osuCrypto::block>, vector<pair<osuCrypto::block, osuCrypto::block>>> commitPairSimulated =
    PartyA::commitEncsA(lambda, kappa, seedsA, &ivAsim, encsSimulated);
  vector<osuCrypto::block> commitmentsEncsASimulated = commitPairSimulated.first;
  timeLog->endMark("  commitments encs");

  timeLog->markTime("  commitments circuits");
  pair<vector<osuCrypto::block>, vector<osuCrypto::block>> commitPair = PartyA::commitCircuits(lambda, kappa, circuit, seedsA, &ivAsim, circuits);
  vector<osuCrypto::block> commitmentsA = commitPair.first;
  vector<osuCrypto::block> decommitmentsA = commitPair.second;
  timeLog->endMark("  commitments circuits");

  timeLog->markTime("  check commits");
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
  timeLog->endMark("  check commits");

  timeLog->markTime("  call judge");
  if(callJudge) {
    cout << "B: calling judge" << endl;
    vector<osuCrypto::block> commitmentsEncsAJ;
    int startIndex = 2*j*GV::n1;
    for(int i=0; i<GV::n1; i++) {
      commitmentsEncsAJ.push_back(commitmentsEncsA.at(startIndex+2*i));
      commitmentsEncsAJ.push_back(commitmentsEncsA.at(startIndex+2*i+1));
    }

    SignatureHolder* signatureHolder = signatureHolders.at(j);
    CryptoPP::byte *signature = signatureHolder->getSignature();
    int signatureLength = signatureHolder->getSignatureLength();

    Judge judge(kappa, pk, circuit);
    bool judgement = judge.accuse(j, signature, signatureLength, seedsB.at(j), decommitmentsB.at(j), commitmentsA.at(j), commitmentsEncsAJ,
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
  timeLog->endMark("  call judge");

  timeLog->markTime("  network close");
  socSerSim->close();
  socCliSim->close();
  recSerSim.close();
  recCliSim.close();
  chlSerSim.close();
  chlCliSim.close();
  timeLog->endMark("  network close");
  return true;
}
