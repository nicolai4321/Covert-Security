#include "PartyA.h"
using namespace std;

PartyA::PartyA(int input, CryptoPP::RSA::PrivateKey secretKey, CryptoPP::RSA::PublicKey publicKey, int k, int l,
               CircuitInterface* cI, TimeLog *timelog) {
  x = input;
  sk = secretKey;
  pk = publicKey;
  kappa = k;
  lambda = l;
  circuit = cI;
  timeLog = timelog;
}

PartyA::~PartyA() {}

/*
  Starts the protocol
*/
bool PartyA::startProtocol() {
  //Network
  timeLog->markTime("network setup");
  ios = new osuCrypto::IOService(16);
  chl = osuCrypto::Session(*ios, GV::ADDRESS, osuCrypto::SessionMode::Server).addChannel();
  osuCrypto::SocketInterface *socket = new SocketRecorder(chl);
  socketRecorder = (SocketRecorder*) socket;
  chlOT = osuCrypto::Channel(*ios, socket);
  timeLog->endMark("network setup");

  //Generating random seeds and witnesses
  timeLog->markTime("generating seeds");
  vector<CryptoPP::byte*> seedsA;
  vector<CryptoPP::byte*> witnesses;
  map<unsigned int, unsigned int> iv;
  for(int j=0; j<lambda; j++) {
    CryptoPP::byte *seedA = new CryptoPP::byte[kappa];
    CryptoPP::byte *witnessA = new CryptoPP::byte[kappa];
    Util::randomByte(seedA, kappa);
    Util::randomByte(witnessA, kappa);
    seedsA.push_back(seedA);
    witnesses.push_back(witnessA);
    iv[j] = 0;
  }
  timeLog->endMark("generating seeds");

  //Get the commitments of the seeds from party B
  timeLog->markTime("waiting for commitments");
  vector<osuCrypto::Commit> commitmentsB;
  chl.recv(commitmentsB);
  if(GV::PRINT_NETWORK_COMMUNICATION) cout << "A: has received commitments from other party" << endl;
  timeLog->endMark("waiting for commitments");

  //First OT
  timeLog->markTime("first ot");
  osuCrypto::KosOtExtSender sender;
  otSeedsWitnesses(&sender, lambda, kappa, chlOT, socketRecorder, seedsA, &iv, witnesses);
  if(GV::PRINT_NETWORK_COMMUNICATION) cout << "A: has done first OT" << endl;
  timeLog->endMark("first ot");

  //Garbling
  timeLog->markTime("garbling");
  pair<vector<CircuitInterface*>, map<int, vector<vector<CryptoPP::byte*>>>> garblingInfo = garbling(lambda, kappa, circuit, seedsA);
  vector<CircuitInterface*> circuits = garblingInfo.first;
  map<int, vector<vector<CryptoPP::byte*>>> encs = garblingInfo.second;
  if(GV::PRINT_NETWORK_COMMUNICATION) cout << "A: has done garbling" << endl;
  timeLog->endMark("garbling");

  //Second OT
  timeLog->markTime("second ot");
  otEncs(&sender, lambda, kappa, chlOT, socketRecorder, encs, seedsA, &iv);
  if(GV::PRINT_NETWORK_COMMUNICATION) cout << "A: has done second OT" << endl;
  timeLog->endMark("second ot");

  //Commiting input encodings
  timeLog->markTime("commit encs");
  pair<vector<osuCrypto::Commit>, vector<pair<osuCrypto::block, osuCrypto::block>>> commitPair0 = commitEncsA(lambda, kappa, seedsA, &iv, encs);
  vector<osuCrypto::Commit> commitmentsEncsInputsA = commitPair0.first;
  vector<pair<osuCrypto::block, osuCrypto::block>> decommitmentsEncsA = commitPair0.second;
  timeLog->endMark("commit encs");

  //Commiting circuits
  timeLog->markTime("commit circuits");
  pair<vector<osuCrypto::Commit>, vector<osuCrypto::block>> commitPair1 = commitCircuits(lambda, kappa, circuit, seedsA, &iv, circuits);
  vector<osuCrypto::Commit> commitmentsA = commitPair1.first;
  vector<osuCrypto::block> decommitmentsA = commitPair1.second;
  timeLog->endMark("commit circuits");

  //Construct signatures
  timeLog->markTime("construct signatures");
  vector<SignatureHolder*> signatureHolders = constructSignatures(commitmentsA, commitmentsB, commitmentsEncsInputsA);
  timeLog->endMark("construct signatures");

  timeLog->markTime("sending commitments and signatures");
  if(GV::PRINT_NETWORK_COMMUNICATION) cout << "A: sending commitments for encoded inputs" << endl;
  chl.asyncSend(move(commitmentsEncsInputsA));

  if(GV::PRINT_NETWORK_COMMUNICATION) cout << "A: sending commitments for circuits" << endl;
  chl.asyncSend(move(commitmentsA));

  if(GV::PRINT_NETWORK_COMMUNICATION) cout << "A: sending signatures" << endl;
  chl.asyncSendCopy(signatureHolders);
  timeLog->endMark("sending commitments and signatures");

  //Receive gamma, seeds and witness
  timeLog->markTime("waiting for gamma, witness");
  vector<osuCrypto::block> gammaSeedsWitnessBlock;
  chl.recv(gammaSeedsWitnessBlock);
  if(GV::PRINT_NETWORK_COMMUNICATION) cout << "A: has received gamma, seeds and witness" << endl;
  timeLog->endMark("waiting for gamma, witness");

  timeLog->markTime("checking");

  CryptoPP::byte gammaByte[4];
  Util::blockToByte(gammaSeedsWitnessBlock.at(0), 4, gammaByte);
  int gamma = Util::byteToInt(gammaByte);

  //Checks the seeds and witness
  if(!checkSeedsWitness(gamma, gammaSeedsWitnessBlock, seedsA, witnesses)) {
    chlOT.close();
    chl.close();
    ios->stop();
    return false;
  }
  timeLog->endMark("checking");

  //Send garbled circuit
  timeLog->markTime("export circuit");
  CircuitInterface *circuit = circuits.at(gamma);
  GarbledCircuit *F = circuit->exportCircuit();
  timeLog->endMark("export circuit");

  timeLog->markTime("sending circuit, encodings and decommitments");
  if(GV::PRINT_NETWORK_COMMUNICATION) cout << "A: sending F" << endl;
  chl.asyncSendCopy(F);

  //Sending A's encoding inputs
  if(GV::PRINT_NETWORK_COMMUNICATION) cout << "A: sending my encoded input" << endl;
  chl.asyncSend(move(getEncsInputA(gamma, encs)));

  //Sending A's decommitments for the encoding inputs
  if(GV::PRINT_NETWORK_COMMUNICATION) cout << "A: sending decommits for my input encodings" << endl;
  chl.asyncSend(move(getDecommitmentsInputA(gamma, decommitmentsEncsA)));

  //Sending A's decommitment for the circuit
  if(GV::PRINT_NETWORK_COMMUNICATION) cout << "A: sending decommits for circuits" << endl;
  chl.asyncSend(move(decommitmentsA));
  timeLog->endMark("sending circuit, encodings and decommitments");

  timeLog->markTime("closing network");
  chlOT.close();
  chl.close();
  ios->stop();
  timeLog->endMark("closing network");

  return true;
}

/*
  Garbling the circuits and prepare the ot data
*/
pair<vector<CircuitInterface*>, map<int, vector<vector<CryptoPP::byte*>>>> PartyA::garbling(int lamb,
                                                                                            int kapp,
                                                                                            CircuitInterface* circuitI,
                                                                                            vector<CryptoPP::byte*> seedsA) {
  vector<CircuitInterface*> circuits;
  map<int, vector<vector<CryptoPP::byte*>>> encs;

  for(int j=0; j<lamb; j++) {
    CircuitInterface *G = circuitI->createInstance(kapp, seedsA.at(j));

    CircuitReader cr = CircuitReader();
    cr.setReverseInput(true);
    pair<bool, vector<vector<CryptoPP::byte*>>> import = cr.import(G, GV::filename);
    if(!import.first) {throw runtime_error("Error! Could not import circuit");}

    circuits.push_back(G);
    encs[j] = import.second;
  }

  pair<vector<CircuitInterface*>, map<int, vector<vector<CryptoPP::byte*>>>> output(circuits, encs);
  return output;
}

/*
  First OT-interaction. Sends seedsA and witnesses
*/
void PartyA::otSeedsWitnesses(osuCrypto::KosOtExtSender* sender, int lambd, int kapp, osuCrypto::Channel channel, SocketRecorder *sRecorder,
                              vector<CryptoPP::byte*> seedsA, map<unsigned int, unsigned int>* iv, vector<CryptoPP::byte*> witnesses) {
  sRecorder->forceStore("ot1", lambd, 68, 12);
  for(int j=0; j<lambd; j++) {
    vector<array<osuCrypto::block, 2>> data(1);
    osuCrypto::block block0 = Util::byteToBlock(seedsA.at(j), kapp);
    osuCrypto::block block1 = Util::byteToBlock(witnesses.at(j), kapp);
    data[0] = {block0, block1};

    CryptoPP::byte seedInput[kapp];
    (*iv)[j] = Util::randomByte(seedInput, kapp, seedsA.at(j), kapp, (*iv)[j]);

    osuCrypto::PRNG prng(Util::byteToBlock(seedInput, kapp));
    sender->genBaseOts(prng, channel);
    sender->sendChosen(data, prng, channel);
  }
}

/*
  Second OT-interaction. Sends input encodings for party B
*/
void PartyA::otEncs(osuCrypto::KosOtExtSender* sender, int lambd, int kapp, osuCrypto::Channel channel, SocketRecorder *sRecorder,
                    map<int, vector<vector<CryptoPP::byte*>>> encs, vector<CryptoPP::byte*> seedsA, map<unsigned int, unsigned int>* iv) {
  sRecorder->forceStore("ot2", lambd, 68, 12);
  for(int j=0; j<lambd; j++) {
    vector<array<osuCrypto::block, 2>> data(GV::n2);
    for(int i=0; i<GV::n2; i++) {
      osuCrypto::block block0 = Util::byteToBlock(encs[j].at(GV::n1+i).at(0), kapp);
      osuCrypto::block block1 = Util::byteToBlock(encs[j].at(GV::n1+i).at(1), kapp);
      data[i] = {block0, block1};
    }

    CryptoPP::byte seedInput[kapp];
    (*iv)[j] = Util::randomByte(seedInput, kapp, seedsA.at(j), kapp, (*iv)[j]);

    osuCrypto::PRNG prng(Util::byteToBlock(seedInput, kapp));
    sender->genBaseOts(prng, channel);
    sender->sendChosen(data, prng, channel);
  }
}

/*
  Checks that party A has correct seeds and witness
*/
bool PartyA::checkSeedsWitness(int gamma, vector<osuCrypto::block> gammaSeedsWitnessBlock, vector<CryptoPP::byte*> seedsA, vector<CryptoPP::byte*> witnesses) {
  for(int j=0; j<lambda; j++) {
    CryptoPP::byte b[kappa];
    Util::blockToByte(gammaSeedsWitnessBlock.at(j+1), kappa, b);
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

/*
  This function returns the input encodings for party A
*/
vector<osuCrypto::block> PartyA::getEncsInputA(int gamma, map<int, vector<vector<CryptoPP::byte*>>> encs) {
  vector<osuCrypto::block> encsInputsA;
  vector<vector<CryptoPP::byte*>> circuitEncs = encs[gamma];
  string xBitString = bitset<GV::n1>(x).to_string();
  for(int j=0; j<GV::n1; j++) {
    int b = (int) xBitString[j] - 48;
    encsInputsA.push_back(Util::byteToBlock(circuitEncs.at(j).at(b), kappa));
  }
  return encsInputsA;
}

/*
  This function returns the decommitment for party A's input encodings
*/
vector<osuCrypto::block> PartyA::getDecommitmentsInputA(int gamma, vector<pair<osuCrypto::block, osuCrypto::block>> decommitmentsEncsA) {
  vector<osuCrypto::block> decommitmentsInputA;
  string xBitString = bitset<GV::n1>(x).to_string();
  for(int j=0; j<GV::n1; j++) {
    pair<osuCrypto::block, osuCrypto::block> p = decommitmentsEncsA.at(j+(GV::n1*gamma));
    int b = (int) xBitString[j] - 48;
    osuCrypto::block decommit = (b) ? p.second : p.first;
    decommitmentsInputA.push_back(decommit);
  }
  return decommitmentsInputA;
}

/*
  Auxillery function for commitEncsA
*/
void PartyA::auxCommitEncsA(int j, int kapp, CryptoPP::byte* seedA,
                            map<unsigned int, unsigned int>* iv,
                            vector<vector<CryptoPP::byte*>> encs,
                            vector<osuCrypto::Commit>* commitmentsEncsInputsA,
                            vector<pair<osuCrypto::block, osuCrypto::block>>* decommitmentsEncsA) {
  for(int i=0; i<GV::n1; i++) {
    CryptoPP::byte decom0[kapp];
    CryptoPP::byte decom1[kapp];
    (*iv)[j] = Util::randomByte(decom0, kapp, seedA, kapp, (*iv)[j]);
    (*iv)[j] = Util::randomByte(decom1, kapp, seedA, kapp, (*iv)[j]);

    osuCrypto::block decommit0 = Util::byteToBlock(decom0, kapp);
    osuCrypto::block decommit1 = Util::byteToBlock(decom1, kapp);

    osuCrypto::Commit c0 = Util::commit(Util::byteToBlock(encs.at(i).at(0), kapp), decommit0);
    osuCrypto::Commit c1 = Util::commit(Util::byteToBlock(encs.at(i).at(1), kapp), decommit1);

    pair<osuCrypto::block, osuCrypto::block> p;
    p.first = decommit0;
    p.second = decommit1;
    decommitmentsEncsA->push_back(p);

    //Random order so that party B cannot extract my input when I give him decommitments
    if(Util::randomInt(0, 1, seedA, kapp, (*iv)[j])) {
      commitmentsEncsInputsA->push_back(c0);
      commitmentsEncsInputsA->push_back(c1);
    } else {
      commitmentsEncsInputsA->push_back(c1);
      commitmentsEncsInputsA->push_back(c0);
    }
    (*iv)[j] = (*iv)[j]+1;
  }
}

/*
  This function returns a pair where the first entry is
  a list of commitments for the encoding inputs and the
  second entry is the decommitments
*/
pair<vector<osuCrypto::Commit>, vector<pair<osuCrypto::block, osuCrypto::block>>>
PartyA::commitEncsA(int lamb, int kapp, vector<CryptoPP::byte*> seedsA, map<unsigned int, unsigned int>* iv, map<int, vector<vector<CryptoPP::byte*>>> encs) {
  vector<osuCrypto::Commit> commitmentsEncsInputsA;
  vector<pair<osuCrypto::block, osuCrypto::block>> decommitmentsEncsA;
  for(int j=0; j<lamb; j++) {
    auxCommitEncsA(j, kapp, seedsA.at(j), iv, encs[j], &commitmentsEncsInputsA, &decommitmentsEncsA);
  }

  pair<vector<osuCrypto::Commit>, vector<pair<osuCrypto::block, osuCrypto::block>>> output(commitmentsEncsInputsA, decommitmentsEncsA);
  return output;
}

/*
  This function returns a pair where the first entry is
  a list of commitments for the circuits and the second
  entry is the decommitments
*/
pair<vector<osuCrypto::Commit>, vector<osuCrypto::block>> PartyA::commitCircuits(int lamb, int kapp, CircuitInterface *cir, vector<CryptoPP::byte*> seedsA,
                                                                                map<unsigned int, unsigned int>* iv, vector<CircuitInterface*> circuits) {
  vector<osuCrypto::Commit> commitmentsA;
  vector<osuCrypto::block> decommitmentsA;

  for(int j=0; j<lamb; j++) {
    GarbledCircuit *F = circuits.at(j)->exportCircuit();

    CryptoPP::byte decom[kapp];
    (*iv)[j] = Util::randomByte(decom, kapp, seedsA.at(j), kapp, (*iv)[j]);

    osuCrypto::block decommit = Util::byteToBlock(decom, kapp);
    osuCrypto::Commit c = commitCircuit(kapp, cir->getType(), F, decommit);

    decommitmentsA.push_back(decommit);
    commitmentsA.push_back(c);
  }

  pair<vector<osuCrypto::Commit>, vector<osuCrypto::block>> output(commitmentsA, decommitmentsA);
  return output;
}

/*
  This function commits one garbled circuit
*/
osuCrypto::Commit PartyA::commitCircuit(int kapp, string type, GarbledCircuit *F, osuCrypto::block decommit) {
  vector<pair<CryptoPP::byte*,int>> commitQueue;
  int totalLength = 0;

  //constants
  pair<CryptoPP::byte*, CryptoPP::byte*> p = F->getConstants();
  pair<CryptoPP::byte*, int> p0(p.first, kapp);
  pair<CryptoPP::byte*, int> p1(p.second, kapp);
  commitQueue.push_back(p0);
  commitQueue.push_back(p1);
  totalLength += 2*kapp;

  //decodings
  for(vector<CryptoPP::byte*> v : F->getDecodings()) {
    pair<CryptoPP::byte*, int> p2(v.at(0), kapp);
    pair<CryptoPP::byte*, int> p3(v.at(1), kapp);
    commitQueue.push_back(p2);
    commitQueue.push_back(p3);
    totalLength += 2*kapp;
  }

  //garbled tables or and-encodings
  if(type.compare(NormalCircuit::TYPE) == 0) {
    map<string, vector<CryptoPP::byte*>> encData = F->getGarbledTables();
    map<string, vector<CryptoPP::byte*>>::iterator it = encData.begin();
    it = encData.begin();
    while(it != encData.end()) {
      string gateName = it->first;
      vector<CryptoPP::byte*> v = encData[gateName];

      for(CryptoPP::byte *b : v) {
        pair<CryptoPP::byte*, int> p4(b, 2*kapp);
        commitQueue.push_back(p4);
        totalLength += 2*kapp;
      }
      it++;
    }
  } else {
    map<string, vector<CryptoPP::byte*>> encData = F->getAndEncodings();
    map<string, vector<CryptoPP::byte*>>::iterator it = encData.begin();
    while(it != encData.end()) {
      string gateName = it->first;
      vector<CryptoPP::byte*> v = encData[gateName];

      for(CryptoPP::byte *b : v) {
        pair<CryptoPP::byte*, int> p4(b, kapp);
        commitQueue.push_back(p4);
        totalLength += kapp;
      }
      it++;
    }
  }

  return Util::commit(commitQueue, decommit, totalLength);
}

/*
  This function constructs a signature string
*/
pair<CryptoPP::byte*,int> PartyA::constructSignatureByte(int j, int kapp, osuCrypto::Commit *commitmentA, osuCrypto::Commit *commitmentB,
                                        vector<osuCrypto::Commit> *commitmentsEncsInputsA,
                                        vector<pair<int, unsigned char*>> *transcriptSent1,
                                        vector<pair<int, unsigned char*>> *transcriptRecv1,
                                        vector<pair<int, unsigned char*>> *transcriptSent2,
                                        vector<pair<int, unsigned char*>> *transcriptRecv2) {
  vector<pair<CryptoPP::byte*,int>> bytes;
  int bytesSize = 0;

  //Circuit
  string filepath = "circuits/"+GV::filename;
  ifstream reader(filepath);
  reader >> noskipws;
  vector<unsigned char> circuitVector((istream_iterator<unsigned char>(reader)), (istream_iterator<unsigned char>()));
  CryptoPP::byte *circuitByte = new CryptoPP::byte[circuitVector.size()];
  circuitByte = &circuitVector[0];
  pair<CryptoPP::byte*, int> p0(circuitByte, circuitVector.size());
  bytes.push_back(p0);
  bytesSize += circuitVector.size();
  reader.close();

  //Commitments from A
  pair<CryptoPP::byte*, int> p1(commitmentA->data(), commitmentA->size());
  bytes.push_back(p1);
  bytesSize += commitmentA->size();

  string comEncsA;
  for(int i=0; i<GV::n1; i++) {
    pair<CryptoPP::byte*, int> p2(commitmentsEncsInputsA->at(2*i).data(), commitmentsEncsInputsA->at(2*i).size());
    pair<CryptoPP::byte*, int> p3(commitmentsEncsInputsA->at(2*i+1).data(), commitmentsEncsInputsA->at(2*i+1).size());
    bytes.push_back(p2);
    bytes.push_back(p3);
    bytesSize += commitmentsEncsInputsA->at(2*i).size();
    bytesSize += commitmentsEncsInputsA->at(2*i+1).size();
  }

  //Commitments from B
  pair<CryptoPP::byte*, int> p4(commitmentB->data(), commitmentB->size());
  bytes.push_back(p4);
  bytesSize += commitmentB->size();

  //Transcripts
  for(pair<int, unsigned char*> p : (*transcriptSent1)) {
    pair<CryptoPP::byte*, int> p5(p.second, p.first);
    bytes.push_back(p5);
    bytesSize += p.first;
  }

  for(pair<int, unsigned char*> p : (*transcriptRecv1)) {
    pair<CryptoPP::byte*, int> p6(p.second, p.first);
    bytes.push_back(p6);
    bytesSize += p.first;
  }

  for(pair<int, unsigned char*> p : (*transcriptSent2)) {
    pair<CryptoPP::byte*, int> p7(p.second, p.first);
    bytes.push_back(p7);
    bytesSize += p.first;
  }

  for(pair<int, unsigned char*> p : (*transcriptRecv2)) {
    pair<CryptoPP::byte*, int> p8(p.second, p.first);
    bytes.push_back(p8);
    bytesSize += p.first;
  }

  CryptoPP::byte *outputByte = new CryptoPP::byte[bytesSize];
  int counter = 0;
  for(pair<CryptoPP::byte*, int> p : bytes) {
      memcpy(outputByte+counter, p.first, p.second);
      counter += p.second;
  }

  pair<CryptoPP::byte*, int> output;
  output.first = outputByte;
  output.second = bytesSize;
  return output;
}

/*
  This function constructs the signatures
*/
vector<SignatureHolder*> PartyA::constructSignatures(vector<osuCrypto::Commit> commitmentsA, vector<osuCrypto::Commit> commitmentsB,
                                                     vector<osuCrypto::Commit> commitmentsEncsInputsA) {
  vector<SignatureHolder*> output;
  for(int j=0; j<lambda; j++) {
    vector<osuCrypto::Commit> commitmentsEncsInputsAJ;
    int startIndex = 2*j*GV::n1;
    for(int i=0; i<GV::n1; i++) {
      commitmentsEncsInputsAJ.push_back(commitmentsEncsInputsA.at(startIndex+2*i));
      commitmentsEncsInputsAJ.push_back(commitmentsEncsInputsA.at(startIndex+2*i+1));
    }
    pair<CryptoPP::byte*, int> msg = constructSignatureByte(j, kappa, &commitmentsA.at(j), &commitmentsB.at(j), &commitmentsEncsInputsAJ,
                                                            socketRecorder->getSentCat("ot1"+to_string(j)),
                                                            socketRecorder->getRecvCat("ot1"+to_string(j)),
                                                            socketRecorder->getSentCat("ot2"+to_string(j)),
                                                            socketRecorder->getRecvCat("ot2"+to_string(j)));
    pair<CryptoPP::SecByteBlock, size_t> signature = Signature::sign(sk, msg.first, msg.second);
    SignatureHolder *signatureHolder = new SignatureHolder(msg.first, msg.second, signature.first, signature.second);
    output.push_back(signatureHolder);
  }
  return output;
}
