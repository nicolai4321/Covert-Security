#include "PartyB.h"
using namespace std;

PartyB::PartyB(int input, CryptoPP::RSA::PublicKey publicKey, int k, int l, CircuitInterface* cir, EvaluatorInterface* eI, TimeLog *timelog) {
  y = input;
  pk = publicKey;
  kappa = k;
  lambda = l;
  circuit = cir;
  evaluator = eI;
  timeLog = timelog;
}

PartyB::~PartyB() {}

/*
  Starts the protocol
*/
bool PartyB::startProtocol() {
  //Network
  timeLog->markTime("network setup");
  osuCrypto::IOService ios(16);
  chl = osuCrypto::Session(ios, GV::ADDRESS, osuCrypto::SessionMode::Client).addChannel();
  osuCrypto::SocketInterface *socket= new SocketRecorder(chl);
  socketRecorder = (SocketRecorder*) socket;
  chlOT = osuCrypto::Channel(ios, socket);
  timeLog->endMark("network setup");

  //Gamma
  timeLog->markTime("generate gamma, seeds");
  gamma = Util::randomInt(0, lambda-1);

  //Generating random seeds
  vector<CryptoPP::byte*> seedsB;
  map<unsigned int, unsigned int> ivB;
  for(int j=0; j<lambda; j++) {
    CryptoPP::byte *seedB = new CryptoPP::byte[kappa];
    Util::randomByte(seedB, kappa);
    seedsB.push_back(seedB);
    ivB[j] = 0;
  }
  timeLog->endMark("generate gamma, seeds");

  //Commitments of the seeds for party B
  timeLog->markTime("generate commitments of own seed");
  vector<osuCrypto::Commit> commitmentsBSend;
  vector<osuCrypto::Commit> commitmentsB;
  vector<osuCrypto::block> decommitmentsB;
  for(int j=0; j<lambda; j++) {
    CryptoPP::byte rInput[kappa];
    Util::randomByte(rInput, kappa);
    osuCrypto::block r = Util::byteToBlock(rInput, kappa);
    osuCrypto::Commit c = Util::commit(Util::byteToBlock(seedsB.at(j), kappa), r);
    commitmentsB.push_back(c);
    commitmentsBSend.push_back(c);
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

  //simulate garbling
  timeLog->markTime("simulate garbling");
  if(GV::PRINT_NETWORK_COMMUNICATION) cout << "B: simulate garbling" << endl;
  vector<CryptoPP::byte*> seedsA;
  for(int j=0; j<lambda; j++) {
    CryptoPP::byte *seedA = new CryptoPP::byte[kappa];
    Util::blockToByte(seedsWitnessA.at(j), kappa, seedA);
    seedsA.push_back(seedA);
  }
  pair<vector<CircuitInterface*>, map<int, vector<vector<CryptoPP::byte*>>>> garblingInfo = PartyA::garbling(lambda, kappa, circuit, seedsA);

  //store basic information (independent of seed)
  GarbledCircuit *gC = new GarbledCircuit();
  garblingInfo.first.at(0)->exportCircuit(gC);
  gateOrderB = gC->getGateOrder();
  outputGatesB = gC->getOutputGates();
  gateInfoB = gC->getGateInfo();
  if(GV::PRINT_NETWORK_COMMUNICATION) cout << "B: done simulate garbling" << endl;
  timeLog->endMark("simulate garbling");

  //Second OT
  timeLog->markTime("2nd ot");
  vector<osuCrypto::block> encsInputsB = otEncodingsB(&recver, y, lambda, kappa, gamma, chlOT, socketRecorder, seedsB, &ivB);
  if(GV::PRINT_NETWORK_COMMUNICATION) cout << "B: has done second OT" << endl;
  timeLog->endMark("2nd ot");

  //Receive commitments
  timeLog->markTime("waiting for commitments");
  vector<osuCrypto::Commit> commitmentsEncsA;
  chl.recv(commitmentsEncsA);
  if(GV::PRINT_NETWORK_COMMUNICATION) cout << "B: has received commitments for input encodings from other party" << endl;
  vector<osuCrypto::Commit> commitmentsCircuitsA;
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
  if(!simulatePartyA(&ios, &recver, seedsB, signatureHolders, seedsA, commitmentsEncsA, commitmentsCircuitsA, commitmentsB, decommitmentsB, garblingInfo)) {
    chlOT.close();
    chl.close();
    ios.stop();
    return false;
  }
  timeLog->endMark("simulate");

  //Sends gamma, witness and seeds to other party
  timeLog->markTime("send gamma seed witness");
  vector<osuCrypto::block> gammaSeedsWitnessBlock;

  CryptoPP::byte gammaByte[sizeof(int)];
  memcpy(gammaByte, &gamma, sizeof(int));

  gammaSeedsWitnessBlock.push_back(Util::byteToBlock(gammaByte, sizeof(int)));
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
    ios.stop();
    return false;
  }
  timeLog->endMark("checking commits");

  chlOT.close();
  chl.close();
  ios.stop();

  timeLog->markTime("evaluate");
  bool output = evaluate(F, encsInputsA, encsInputsB);
  timeLog->endMark("evaluate");

  //Free memory
  for(CryptoPP::byte *seedA : seedsA) {
    delete seedA;
  }
  for(CryptoPP::byte *seedB : seedsB) {
    delete seedB;
  }
  delete gC;

  return output;
}

/*
  First OT-interaction. Receives seeds and witnesses for A
*/
vector<osuCrypto::block> PartyB::otSeedsWitnessA(osuCrypto::KosOtExtReceiver* recver, osuCrypto::Channel channel, SocketRecorder *sRecorder, vector<CryptoPP::byte*> seedsB,
                                                 map<unsigned int, unsigned int>* ivB) {
  vector<osuCrypto::block> seedsWitnessA;
  sRecorder->scheduleStore("ot1", lambda, 12, 68);
  for(int j=0; j<lambda; j++) {
    osuCrypto::BitVector b(1);
    b[0] = (j==gamma) ? 1 : 0;

    CryptoPP::byte seedInput[kappa];
    (*ivB)[j] = Util::randomByte(seedInput, kappa, seedsB.at(j), kappa, (*ivB)[j]);

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
  string yString = bitset<GV::n2>(input).to_string();

  vector<osuCrypto::block> encsB;
  sRecorder->scheduleStore("ot2", lambd, 12, 68);
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

    CryptoPP::byte seedInput[kapp];
    (*ivB)[j] = Util::randomByte(seedInput, kapp, seed, kapp, (*ivB)[j]);
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
bool PartyB::checkCommitments(GarbledCircuit* F,
                              vector<osuCrypto::block> decommitmentsEncA,
                              vector<osuCrypto::block> decommitmentsCircuitA,
                              vector<osuCrypto::Commit> commitmentsEncsA,
                              vector<osuCrypto::Commit> commitmentsCircuitsA,
                              vector<osuCrypto::block> encsInputsA) {
  CryptoPP::byte *commitSim = PartyA::commitCircuit(kappa, circuit->getType(), F, decommitmentsCircuitA.at(gamma)).data();
  CryptoPP::byte *commit = commitmentsCircuitsA.at(gamma).data();
  int sizCircuitCommit = commitmentsCircuitsA.at(gamma).size();

  if(memcmp(commitSim, commit, sizCircuitCommit) != 0) {
    cout << "B: Error! Invalid circuit commitment from other party (lambda)" << endl;
    return false;
  }

  //Checking input encodings
  int startIndex = 2*gamma*GV::n1;
  for(int i=0; i<GV::n1; i++) {
    osuCrypto::block decommit = decommitmentsEncA.at(i);
    osuCrypto::Commit c = Util::commit(encsInputsA.at(i), decommit);
    CryptoPP::byte* c0 = commitmentsEncsA.at(startIndex+2*i).data();
    CryptoPP::byte* c1 = commitmentsEncsA.at(startIndex+2*i+1).data();

    if(memcmp(c.data(), c0, c.size()) != 0 && memcmp(c.data(), c1, c.size()) != 0) {
      cout << "B: Error! Invalid input encoding commitment from other party (lambda)" << endl;
      return false;
    }
  }

  //Checking gate order
  vector<string> gateOrderA = F->getGateOrder();
  if(gateOrderA.size() != gateOrderB.size()) {
    cout << "B: Error! Not same amount of gates (lambda)" << endl;
    return false;
  }
  for(int i=0; i<gateOrderA.size(); i++) {
    if(gateOrderA.at(i).compare(gateOrderB.at(i)) != 0) {
      cout << "B: Error! Gate order does not match (lambda)" << endl;
      return false;
    }
  }

  //Checking output gates
  vector<string> outputGatesA = F->getOutputGates();
  if(outputGatesA.size() != outputGatesB.size()) {
    cout << "B: Error! Not same amount of output gates (lambda)" << endl;
    return false;
  }
  for(int i=0; i<outputGatesA.size(); i++) {
    if(outputGatesA.at(i).compare(outputGatesB.at(i)) != 0) {
      cout << "B: Error! Output gates does not match (lambda)" << endl;
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
      cout << "B: Error! Gate info does not match (lambda)" << endl;
      return false;
    }
    itA++;
    itB++;
  }
  if(itA != gateInfoA.end() || itB != gateInfoB.end()) {
    cout << "B: Error! Size of gate info does not match (lambda)" << endl;
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
    CryptoPP::byte *encInput = new CryptoPP::byte[kappa];
    Util::blockToByte(encsInputsA.at(j), kappa, encInput);
    encsInputs.push_back(encInput);
  }
  for(int j=0; j<GV::n2; j++) {
    CryptoPP::byte *encInput = new CryptoPP::byte[kappa];
    Util::blockToByte(encsInputsB.at(j), kappa, encInput);
    encsInputs.push_back(encInput);
  }

  evaluator->giveCircuit(F);
  pair<bool, vector<CryptoPP::byte*>> evaluated = evaluator->evaluate(encsInputs);

  for(CryptoPP::byte *encInput : encsInputs) {
    delete encInput;
  }

  if(evaluated.first) {
    pair<bool, vector<bool>> decoded = evaluator->decode(evaluated.second);
    if(decoded.first) {
      vector<bool> output = decoded.second;
      cout << "B: Output,";

      for(int i=output.size()-1; i>=0; i--) {
        cout << output.at(i);
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
bool PartyB::simulatePartyA(osuCrypto::IOService *ios,
                            osuCrypto::KosOtExtReceiver *recver,
                            vector<CryptoPP::byte*> seedsB,
                            vector<SignatureHolder*> signatureHolders,
                            vector<CryptoPP::byte*> seedsA,
                            vector<osuCrypto::Commit> commitmentsEncsA,
                            vector<osuCrypto::Commit> commitmentsCircuitsA,
                            vector<osuCrypto::Commit> commitmentsB,
                            vector<osuCrypto::block> decommitmentsB,
                            pair<vector<CircuitInterface*>, map<int, vector<vector<CryptoPP::byte*>>>> garblingInfoSim) {
  //Checking signatures
  timeLog->markTime("  check signatures");
  if(GV::PRINT_NETWORK_COMMUNICATION) cout << "B: checking signatures" << endl;
  for(int j=0; j<lambda; j++) {
    SignatureHolder *signatureHolder = signatureHolders.at(j);
    if(!Signature::verify(pk, signatureHolder)) {
      cout << "B: found invalid signature" << endl;
      return false;
    }
  }
  timeLog->endMark("  check signatures");

  //Generating seeds
  timeLog->markTime("  iv");
  if(GV::PRINT_NETWORK_COMMUNICATION) cout << "B: generating ivs" << endl;
  map<unsigned int, unsigned int> ivAsim;
  map<unsigned int, unsigned int> ivBSim;
  for(int j=0; j<lambda; j++) {
    ivAsim[j] = 1;
    ivBSim[j] = 1;
  }
  timeLog->endMark("  iv");

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
  map<int, vector<vector<CryptoPP::byte*>>> encsSimulated = garblingInfoSim.second;
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
      vector<osuCrypto::Commit> commitmentsEncsAJ;
      int startIndex = 2*j*GV::n1;
      for(int i=0; i<GV::n1; i++) {
        commitmentsEncsAJ.push_back(commitmentsEncsA.at(startIndex+2*i));
        commitmentsEncsAJ.push_back(commitmentsEncsA.at(startIndex+2*i+1));
      }
      timeLog->endMark("    find commitments for encs"+to_string(j));

      timeLog->markTime("    construct signature string"+to_string(j));
      vector<pair<int, unsigned char*>> transcriptSent1;
      vector<pair<int, unsigned char*>> transcriptRecv1;
      vector<pair<int, unsigned char*>> transcriptSimSent2;
      vector<pair<int, unsigned char*>> transcriptSimRecv2;
      socketRecorder->getSentCat("ot1"+to_string(j), &transcriptSent1);
      socketRecorder->getRecvCat("ot1"+to_string(j), &transcriptRecv1);
      socSerSim->getSentCat("ot2"+to_string(j), &transcriptSimSent2);
      socSerSim->getRecvCat("ot2"+to_string(j), &transcriptSimRecv2);

      pair<CryptoPP::byte*,int> msgSim = PartyA::constructSignatureByte(j, kappa, &commitmentsCircuitsA.at(j), &commitmentsB.at(j), &commitmentsEncsAJ,
                                                                         &transcriptRecv1,
                                                                         &transcriptSent1,
                                                                         &transcriptSimSent2,
                                                                         &transcriptSimRecv2);
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
      delete msgSim.first;
    }
  }
  timeLog->endMark("  check transscripts");

  //Checking commitments
  timeLog->markTime("  commitments encs");
  pair<vector<osuCrypto::Commit>, vector<pair<osuCrypto::block, osuCrypto::block>>> commitPairSimulated =
    PartyA::commitEncsA(lambda, kappa, seedsA, &ivAsim, encsSimulated);
  vector<osuCrypto::Commit> commitmentsEncsASimulated = commitPairSimulated.first;
  timeLog->endMark("  commitments encs");

  timeLog->markTime("  commitments circuits");
  vector<CircuitInterface*> circuits = garblingInfoSim.first;
  pair<vector<osuCrypto::Commit>, vector<osuCrypto::block>> commitPair = PartyA::commitCircuits(lambda, kappa, circuit, seedsA, &ivAsim, circuits);
  vector<osuCrypto::Commit> commitmentsA = commitPair.first;
  vector<osuCrypto::block> decommitmentsA = commitPair.second;
  timeLog->endMark("  commitments circuits");

  timeLog->markTime("  check commits");
  bool callJudge = false;
  int j;
  for(j=0; j<lambda; j++) {
    if(j != gamma) {
      int startIndex = 2*j*GV::n1;
      for(int i=0; i<GV::n1; i++) {
        osuCrypto::Commit commitSimulated0 = commitmentsEncsASimulated.at(startIndex+2*i);
        osuCrypto::Commit commitReceived0 = commitmentsEncsA.at(startIndex+2*i);
        osuCrypto::Commit commitSimulated1 = commitmentsEncsASimulated.at(startIndex+2*i+1);
        osuCrypto::Commit commitReceived1 = commitmentsEncsA.at(startIndex+2*i+1);

        if(commitSimulated0.size() != commitReceived0.size() || commitSimulated1.size() != commitReceived1.size()) {
          cout << "B: Corrupt! Simulation of commitments for input encodings does not have same length" << endl;
          callJudge = true;
          goto skip;
        }

        if(memcmp(commitSimulated0.data(), commitReceived0.data(), commitSimulated0.size()) != 0 ||
           memcmp(commitSimulated1.data(), commitReceived1.data(), commitSimulated1.size()) != 0) {
          cout << "B: Corrupt! Simulation of commitments for input encodings does not match" << endl;
          callJudge = true;
          goto skip;
        }
      }

      osuCrypto::Commit commitSim1 = commitmentsA.at(j);
      osuCrypto::Commit commitRec1 = commitmentsCircuitsA.at(j);

      if(commitSim1.size() != commitRec1.size()) {
        cout << "B: Corrupt! Simulation of commitments for circuits does not have same length" << endl;
        callJudge = true;
        goto skip;
      }

      if(memcmp(commitSim1.data(), commitRec1.data(), commitSim1.size()) != 0) {
        cout << "B: Corrupt! Simulation of commitments for circuits does not match (" << j << ")" << endl;
        callJudge = true;
        goto skip;
      }
    }
  }
  skip:
  timeLog->endMark("  check commits");

  timeLog->markTime("  judge");
  if(callJudge) {
    cout << "B: calling judge" << endl;
    vector<osuCrypto::Commit> commitmentsEncsAJ;
    int startIndex = 2*j*GV::n1;
    for(int i=0; i<GV::n1; i++) {
      commitmentsEncsAJ.push_back(commitmentsEncsA.at(startIndex+2*i));
      commitmentsEncsAJ.push_back(commitmentsEncsA.at(startIndex+2*i+1));
    }

    SignatureHolder *signatureHolder = signatureHolders.at(j);
    CryptoPP::SecByteBlock signature = signatureHolder->getSignature();
    size_t signatureLength = signatureHolder->getSignatureLength();

    vector<pair<int, unsigned char*>> transcriptSent1;
    vector<pair<int, unsigned char*>> transcriptRecv1;
    vector<pair<int, unsigned char*>> transcriptSimSent2;
    vector<pair<int, unsigned char*>> transcriptSimRecv2;
    socketRecorder->getSentCat("ot1"+to_string(j), &transcriptSent1);
    socketRecorder->getRecvCat("ot1"+to_string(j), &transcriptRecv1);
    socSerSim->getSentCat("ot2"+to_string(j), &transcriptSimSent2);
    socSerSim->getRecvCat("ot2"+to_string(j), &transcriptSimRecv2);

    Judge judge(kappa, pk, circuit);
    bool judgement = judge.accuse(j, signature, signatureLength, seedsB.at(j), decommitmentsB.at(j), commitmentsA.at(j), commitmentsEncsAJ,
                                  &transcriptRecv1,
                                  &transcriptSent1,
                                  &transcriptSimSent2,
                                  &transcriptSimRecv2);

    cout << "B: the judgement is: " << judgement << endl;

    socSerSim->close();
    socCliSim->close();
    recSerSim.close();
    recCliSim.close();
    chlSerSim.close();
    chlCliSim.close();

    return false;
  }
  timeLog->endMark("  judge");

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
