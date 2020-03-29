#include "PartyA.h"
using namespace std;

PartyA::PartyA(int input, CryptoPP::DSA::PrivateKey secretKey, CryptoPP::DSA::PublicKey publicKey, int k, int l, osuCrypto::Channel cOT,
               SocketRecorder *sr, CircuitInterface* cI) {
  x = input;
  sk = secretKey;
  pk = publicKey;
  kappa = k;
  lambda = l;
  chlOT = cOT;
  chl = sr->getMChl();
  socketRecorder = sr;
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
  map<unsigned int, unsigned int> iv;
  for(int j=0; j<lambda; j++) {
    seedsA.push_back(Util::randomByte(kappa));
    witnesses.push_back(Util::randomByte(kappa));
    iv[j] = 0;
  }

  //Get the commitments of the seeds from party B
  vector<osuCrypto::block> commitmentsB;
  chl.recv(commitmentsB);
  cout << "A: has received commitments from other party" << endl;

  //First OT
  osuCrypto::KosOtExtSender sender;
  otSeedsWitnesses(&sender, lambda, kappa, chlOT, socketRecorder, seedsA, &iv, witnesses);
  cout << "A: has done first OT" << endl;

  //Garbling
  pair<vector<CircuitInterface*>, map<int, vector<vector<CryptoPP::byte*>>>> garblingInfo = garbling(lambda, kappa, circuit, seedsA);
  vector<CircuitInterface*> circuits = garblingInfo.first;
  map<int, vector<vector<CryptoPP::byte*>>> encs = garblingInfo.second;
  cout << "A: has done garbling" << endl;

  //Second OT
  otEncs(&sender, lambda, kappa, chlOT, socketRecorder, encs, seedsA, &iv);
  cout << "A: has done second OT" << endl;

  //Commiting input encodings
  pair<vector<osuCrypto::block>, vector<pair<osuCrypto::block, osuCrypto::block>>> commitPair0 = commitEncsA(lambda, kappa, seedsA, &iv, encs);
  vector<osuCrypto::block> commitmentsEncsInputsA = commitPair0.first;
  vector<pair<osuCrypto::block, osuCrypto::block>> decommitmentsEncsA = commitPair0.second;

  //Commiting circuits
  pair<vector<osuCrypto::block>, vector<osuCrypto::block>> commitPair1 = commitCircuits(lambda, kappa, circuit, seedsA, &iv, circuits);
  vector<osuCrypto::block> commitmentsA = commitPair1.first;
  vector<osuCrypto::block> decommitmentsA = commitPair1.second;

  //Construct signatures
  vector<SignatureHolder*> signatureHolders = constructSignatures(commitmentsA, commitmentsB, commitmentsEncsInputsA);

  cout << "A: sending commitments for encoded inputs" << endl;
  chl.asyncSend(move(commitmentsEncsInputsA));

  cout << "A: sending commitments for circuits" << endl;
  chl.asyncSend(move(commitmentsA));

  cout << "A: sending signatures" << endl;
  chl.asyncSendCopy(signatureHolders);

  //Receive gamma, seeds and witness
  vector<osuCrypto::block> gammaSeedsWitnessBlock;
  chl.recv(gammaSeedsWitnessBlock);
  cout << "A: has received gamma, seeds and witness" << endl;
  int gamma = Util::byteToInt(Util::blockToByte(gammaSeedsWitnessBlock.at(0), 4));

  //Checks the seeds and witness
  if(!checkSeedsWitness(gammaSeedsWitnessBlock, seedsA, witnesses)) {return false;}

  //Send garbled circuit
  CircuitInterface *circuit = circuits.at(gamma);
  GarbledCircuit *F = circuit->exportCircuit();
  cout << "A: sending F" << endl;
  chl.asyncSendCopy(F);

  //Sending A's encoding inputs
  cout << "A: sending my encoded input" << endl;
  chl.asyncSend(move(getEncsInputA(gamma, encs)));

  //Sending A's decommitments for the encoding inputs
  cout << "A: sending decommits for my input encodings" << endl;
  chl.asyncSend(move(getDecommitmentsInputA(gamma, decommitmentsEncsA)));

  //Sending A's decommitment for the circuit
  cout << "A: sending decommits for commits" << endl;
  chl.asyncSend(move(decommitmentsA));

  return true;
}

/*
  Garbling the circuits and prepare the ot data
*/
pair<vector<CircuitInterface*>, map<int, vector<vector<CryptoPP::byte*>>>> PartyA::garbling(int lamb, int kapp, CircuitInterface* circuitI, vector<CryptoPP::byte*> seedsA) {
  vector<CircuitInterface*> circuits;
  map<int, vector<vector<CryptoPP::byte*>>> encs;

  for(int j=0; j<lamb; j++) {
    CircuitInterface *G = circuitI->createInstance(kapp, seedsA.at(j));
    CircuitReader cr = CircuitReader();
    pair<bool, vector<vector<CryptoPP::byte*>>> import = cr.import(G, GV::filename);

    if(!import.first) {throw runtime_error("Error! Could not import circuit");}

    circuits.push_back(G);
    encs[j] = import.second;
  }

  pair<vector<CircuitInterface*>, map<int, vector<vector<CryptoPP::byte*>>>> output;
  output.first = circuits;
  output.second = encs;
  return output;
}

/*
  First OT-interaction. Sends seedsA and witnesses
*/
void PartyA::otSeedsWitnesses(osuCrypto::KosOtExtSender* sender, int lambd, int kapp, osuCrypto::Channel channel, SocketRecorder *sRecorder,
                              vector<CryptoPP::byte*> seedsA, map<unsigned int, unsigned int>* iv, vector<CryptoPP::byte*> witnesses) {
  sRecorder->forceStore("ot1", lambd, 4, 10);
  for(int j=0; j<lambd; j++) {
    vector<array<osuCrypto::block, 2>> data(1);
    osuCrypto::block block0 = Util::byteToBlock(seedsA.at(j), kapp);
    osuCrypto::block block1 = Util::byteToBlock(witnesses.at(j), kapp);
    data[0] = {block0, block1};
    CryptoPP::byte *seedInput = Util::randomByte(kapp, seedsA.at(j), (*iv)[j]); (*iv)[j] = (*iv)[j] + 1;
    osuCrypto::PRNG prng(Util::byteToBlock(seedInput, kapp));
    Util::setBaseSer(sender, channel);
    sender->sendChosen(data, prng, channel);
  }
}

/*
  Second OT-interaction. Sends input encodings for party B
*/
void PartyA::otEncs(osuCrypto::KosOtExtSender* sender, int lambd, int kapp, osuCrypto::Channel channel, SocketRecorder *sRecorder,
                    map<int, vector<vector<CryptoPP::byte*>>> encs, vector<CryptoPP::byte*> seedsA, map<unsigned int, unsigned int>* iv) {

  sRecorder->forceStore("ot2", lambd, 4, 10);
  for(int j=0; j<lambd; j++) {
    vector<array<osuCrypto::block, 2>> data(GV::n2);
    for(int i=0; i<GV::n2; i++) {
      osuCrypto::block block0 = Util::byteToBlock(encs[j].at(GV::n1+i).at(0), kapp);
      osuCrypto::block block1 = Util::byteToBlock(encs[j].at(GV::n1+i).at(1), kapp);
      data[i] = {block0, block1};
    }

    CryptoPP::byte* seedInput = Util::randomByte(kapp, seedsA.at(j), (*iv)[j]); (*iv)[j] = (*iv)[j]+1;
    osuCrypto::PRNG prng(Util::byteToBlock(seedInput, kapp));
    Util::setBaseSer(sender, channel);
    sender->sendChosen(data, prng, channel);
  }
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

/*
  This function returns the input encodings for party A
*/
vector<osuCrypto::block> PartyA::getEncsInputA(int gamma, map<int, vector<vector<CryptoPP::byte*>>> encs) {
  vector<osuCrypto::block> encsInputsA;
  vector<vector<CryptoPP::byte*>> circuitEncs = encs[gamma];
  string xBitString = Util::intToBitString(x, GV::n1);
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
  string xBitString = Util::intToBitString(x, GV::n1);
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
void PartyA::auxCommitEncsA(int j, int kapp, CryptoPP::byte* seedA, map<unsigned int, unsigned int>* iv, vector<vector<CryptoPP::byte*>> encs,
                    vector<osuCrypto::block>* commitmentsEncsInputsA, vector<pair<osuCrypto::block, osuCrypto::block>>* decommitmentsEncsA) {
  for(int i=0; i<GV::n1; i++) {
    osuCrypto::block decommit0 = Util::byteToBlock(Util::randomByte(kapp, seedA, (*iv)[j]), kapp); (*iv)[j] = (*iv)[j]+1;
    osuCrypto::block decommit1 = Util::byteToBlock(Util::randomByte(kapp, seedA, (*iv)[j]), kapp); (*iv)[j] = (*iv)[j]+1;

    CryptoPP::byte *c0 = Util::commit(Util::byteToBlock(encs.at(i).at(0), kapp), decommit0);
    CryptoPP::byte *c1 = Util::commit(Util::byteToBlock(encs.at(i).at(1), kapp), decommit1);

    pair<osuCrypto::block, osuCrypto::block> p;
    p.first = decommit0;
    p.second = decommit1;
    decommitmentsEncsA->push_back(p);

    //Random order so that party B cannot extract my input when I give him decommitments
    if(Util::randomInt(0, 1, seedA, (*iv)[j])) {
      commitmentsEncsInputsA->push_back(Util::byteToBlock(c0, Util::COMMIT_LENGTH));
      commitmentsEncsInputsA->push_back(Util::byteToBlock(c1, Util::COMMIT_LENGTH));
    } else {
      commitmentsEncsInputsA->push_back(Util::byteToBlock(c1, Util::COMMIT_LENGTH));
      commitmentsEncsInputsA->push_back(Util::byteToBlock(c0, Util::COMMIT_LENGTH));
    }
    (*iv)[j] = (*iv)[j]+1;
  }
}

/*
  This function returns a pair where the first entry is
  a list of commitments for the encoding inputs and the
  second entry is the decommitments
*/
pair<vector<osuCrypto::block>, vector<pair<osuCrypto::block, osuCrypto::block>>>
PartyA::commitEncsA(int lamb, int kapp, vector<CryptoPP::byte*> seedsA, map<unsigned int, unsigned int>* iv, map<int, vector<vector<CryptoPP::byte*>>> encs) {
  vector<osuCrypto::block> commitmentsEncsInputsA;
  vector<pair<osuCrypto::block, osuCrypto::block>> decommitmentsEncsA;
  for(int j=0; j<lamb; j++) {
    auxCommitEncsA(j, kapp, seedsA.at(j), iv, encs[j], &commitmentsEncsInputsA, &decommitmentsEncsA);
  }

  pair<vector<osuCrypto::block>, vector<pair<osuCrypto::block, osuCrypto::block>>> output;
  output.first = commitmentsEncsInputsA;
  output.second = decommitmentsEncsA;
  return output;
}

/*
  This function returns a pair where the first entry is
  a list of commitments for the circuits and the second
  entry is the decommitments
*/
pair<vector<osuCrypto::block>, vector<osuCrypto::block>> PartyA::commitCircuits(int lamb, int kapp, CircuitInterface *cir, vector<CryptoPP::byte*> seedsA,
                                                                                map<unsigned int, unsigned int>* iv, vector<CircuitInterface*> circuits) {
  pair<vector<osuCrypto::block>, vector<osuCrypto::block>> output;
  vector<osuCrypto::block> commitmentsA;
  vector<osuCrypto::block> decommitmentsA;

  for(int j=0; j<lamb; j++) {
    GarbledCircuit *F = circuits.at(j)->exportCircuit();
    osuCrypto::block decommit = Util::byteToBlock(Util::randomByte(kapp, seedsA.at(j), (*iv)[j]), kapp); (*iv)[j] = (*iv)[j]+1;
    CryptoPP::byte *c = commitCircuit(kapp, cir->getType(), F, decommit);

    decommitmentsA.push_back(decommit);
    commitmentsA.push_back(Util::byteToBlock(c, Util::COMMIT_LENGTH));
  }

  output.first = commitmentsA;
  output.second = decommitmentsA;
  return output;
}

/*
  This function commits one garbled circuit
*/
CryptoPP::byte* PartyA::commitCircuit(int kapp, string type, GarbledCircuit *F, osuCrypto::block decommit) {
  vector<CryptoPP::byte*> commitQueue;

  //constants
  pair<CryptoPP::byte*, CryptoPP::byte*> p = F->getConstants();
  commitQueue.push_back(p.first);
  commitQueue.push_back(p.second);

  //decodings
  for(vector<CryptoPP::byte*> v : F->getDecodings()) {
    commitQueue.push_back(v.at(0));
    commitQueue.push_back(v.at(1));
  }

  //garbled tables or and-encodings
  map<string, vector<CryptoPP::byte*>>::iterator it;
  map<string, vector<CryptoPP::byte*>> encData;
  if(type.compare(NormalCircuit::TYPE) == 0) {
    encData = F->getGarbledTables();
  } else {
    encData = F->getAndEncodings();
  }

  it = encData.begin();
  while(it != encData.end()) {
    string gateName = it->first;
    vector<CryptoPP::byte*> v = encData[gateName];
    for(CryptoPP::byte* b : v) {
      commitQueue.push_back(b);
    }
    it++;
  }

  CryptoPP::byte *c = Util::commit(commitQueue, decommit, kapp);
  return c;
}

/*
  This function constructs a signature string
*/
string PartyA::constructSignatureString(int j, int kapp, osuCrypto::block commitmentA, osuCrypto::block commitmentB,
                                        vector<osuCrypto::block> commitmentsEncsInputsA,
                                        vector<pair<int, unsigned char*>> transcriptSent1,
                                        vector<pair<int, unsigned char*>> transcriptRecv1,
                                        vector<pair<int, unsigned char*>> transcriptSent2,
                                        vector<pair<int, unsigned char*>> transcriptRecv2) {
  //Circuit
  string circuitString = "";
  string line;
  string filepath = "circuits/"+GV::filename;
  ifstream reader;
  reader.open(filepath);
  if(reader.is_open()) {
    while (!reader.eof()) {
      getline(reader, line);
      circuitString += line+"\n";
    }
  } else {
    throw runtime_error("A: Could not read circuit file");
  }

  //Commitments from A
  string comCircuitA = Util::blockToString(commitmentA, kapp);
  string comEncsA;
  for(int i=0; i<GV::n1; i++) {
    comEncsA += Util::blockToString(commitmentsEncsInputsA.at(2*i), kapp);
    comEncsA += Util::blockToString(commitmentsEncsInputsA.at(2*i+1), kapp);
  }

  //Commitments from B
  string comSeedB = Util::blockToString(commitmentB, kapp);

  //Transcripts
  string ot1Sent = "";
  for(pair<int, unsigned char*> p : transcriptSent1) {
    ot1Sent += Util::byteToString(p.second, p.first);
  }

  string ot1Recv = "";
  for(pair<int, unsigned char*> p : transcriptRecv1) {
    ot1Recv += Util::byteToString(p.second, p.first);
  }

  string ot2Sent = "";
  for(pair<int, unsigned char*> p : transcriptSent2) {
    ot2Sent += Util::byteToString(p.second, p.first);
  }

  string ot2Recv = "";
  for(pair<int, unsigned char*> p : transcriptRecv2) {
    ot2Recv += Util::byteToString(p.second, p.first);
  }

  return to_string(j) + circuitString + comSeedB + comCircuitA + comEncsA + ot1Sent + ot1Recv + ot2Sent + ot2Recv;
}

/*
  This function constructs the signatures
*/
vector<SignatureHolder*> PartyA::constructSignatures(vector<osuCrypto::block> commitmentsA, vector<osuCrypto::block> commitmentsB,
                                                     vector<osuCrypto::block> commitmentsEncsInputsA) {
  vector<SignatureHolder*> output;
  for(int j=0; j<lambda; j++) {
    vector<osuCrypto::block> commitmentsEncsInputsAJ;
    int startIndex = 2*j*GV::n1;
    for(int i=0; i<GV::n1; i++) {
      commitmentsEncsInputsAJ.push_back(commitmentsEncsInputsA.at(startIndex+2*i));
      commitmentsEncsInputsAJ.push_back(commitmentsEncsInputsA.at(startIndex+2*i+1));
    }
    string m = constructSignatureString(j, kappa, commitmentsA.at(j), commitmentsB.at(j), commitmentsEncsInputsAJ,
                                        socketRecorder->getSentCat("ot1"+to_string(j)),
                                        socketRecorder->getRecvCat("ot1"+to_string(j)),
                                        socketRecorder->getSentCat("ot2"+to_string(j)),
                                        socketRecorder->getRecvCat("ot2"+to_string(j)));
    string signature = Signature::sign(sk, m);
    SignatureHolder *signatureHolder = new SignatureHolder(m, signature);
    output.push_back(signatureHolder);
  }
  return output;
}
