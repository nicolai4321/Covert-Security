#include "Judge.h"
using namespace std;

bool Judge::accuse(int j, string signature, CryptoPP::byte* seedB, osuCrypto::block decommitB, osuCrypto::block commitA, vector<osuCrypto::block> commitEncsA,
                   vector<pair<int, unsigned char*>> transcriptSent1,
                   vector<pair<int, unsigned char*>> transcriptRecv1,
                   vector<pair<int, unsigned char*>> transcriptSent2,
                   vector<pair<int, unsigned char*>> transcriptRecv2) {
  CryptoPP::byte *commit = Util::commit(Util::byteToBlock(seedB, kappa), decommitB);
  osuCrypto::block commitB = Util::byteToBlock(commit, Util::COMMIT_LENGTH);

  string signatureMsg = PartyA::constructSignatureString(j, kappa, commitA, commitB, commitEncsA, transcriptSent1,
                                                         transcriptRecv1, transcriptSent2, transcriptRecv2);
  bool correctSignature = Signature::verify(pk, signature, signatureMsg);
  if(!correctSignature) {
    cout << "J: The signature is not correct" << endl;
    return false;
  }

  //Network
  osuCrypto::IOService ios(16);
  osuCrypto::Channel chlSer = osuCrypto::Session(ios, GV::ADDRESS_JUDGE, osuCrypto::SessionMode::Server).addChannel();
  osuCrypto::Channel chlCli = osuCrypto::Session(ios, GV::ADDRESS_JUDGE, osuCrypto::SessionMode::Client).addChannel();
  osuCrypto::SocketInterface *siSer = new SocketRecorder(chlSer);
  osuCrypto::SocketInterface *siCli= new SocketRecorder(chlCli);
  SocketRecorder *socketRecorderServer = (SocketRecorder*) siSer;
  SocketRecorder *socketRecorderClient = (SocketRecorder*) siCli;
  osuCrypto::Channel recSer(ios, siSer);
  osuCrypto::Channel recCli(ios, siCli);
  chlCli.waitForConnection();
  recCli.waitForConnection();

  CryptoPP::byte *seedA;

  auto threadCli = thread([&]() {
    osuCrypto::KosOtExtReceiver recver;
    Util::setBaseCli(&recver, recCli, seedB, kappa);

    int iv = 0;
    CryptoPP::byte *seedInput = Util::randomByte(kappa, seedB, iv);
    osuCrypto::PRNG prng(Util::byteToBlock(seedInput, kappa));
    osuCrypto::BitVector choices(1);
    choices[0] = 0;
    vector<osuCrypto::block> seedAblock(1);
    recver.receiveChosen(choices, seedAblock, prng, recCli);
    seedA = Util::blockToByte(seedAblock[0], kappa);
  });

  //This thread below does the OT with the transcript
  //that is signed. The received messages is not stored here
  //since they are stored in the socket recorder object.
  auto threadSer = thread([&]() {
    array<int, 4> b0;
    recSer.recv(b0);

    array<int, 5> b1;
    recSer.recv(b1);

    array<int, 4096> b2;
    recSer.recv(b2);

    recSer.send(transcriptSent1.at(1).second, transcriptSent1.at(1).first);

    array<int, 4> b3;
    recSer.recv(b3);

    array<int, 12> b4;
    recSer.recv(b4);

    recSer.send(transcriptSent1.at(3).second, transcriptSent1.at(3).first);
  });

  threadSer.join();
  threadCli.join();

  //Checks that the received messages have same length
  vector<pair<int, CryptoPP::byte*>> transcriptSimRecv1 = socketRecorderServer->getRecvCat("def");
  if(transcriptSimRecv1.size() != transcriptRecv1.size()) {
    cout << "J: The transcripts have incorrect size!" << endl;
    return false;
  }

  //Checks that the received messages are identical
  for(int i=0; i<transcriptSimRecv1.size(); i++) {
    pair<int, CryptoPP::byte*> p0 = transcriptSimRecv1.at(i);
    pair<int, CryptoPP::byte*> p1 = transcriptRecv1.at(i);
    if(memcmp(p0.second, p1.second, p1.first) != 0) {
      cout << "J: The transcripts are not identical!" << endl;
      return false;
    }
  }
  cout << "J: correct transcripts for 1st ot" << endl;

  recCli.close();
  recSer.close();
  chlCli.close();
  chlSer.close();
  ios.stop();

  //Simulated garbling
  CircuitInterface *circuitInstance = circuit->createInstance(kappa, seedA);
  CircuitReader cr = CircuitReader();
  pair<bool, vector<vector<CryptoPP::byte*>>> import = cr.import(circuitInstance, GV::filename);
  if(!import.first) {throw runtime_error("J: Error! Could not import circuit");}
  vector<vector<CryptoPP::byte*>> encsSim = import.second;

  //Checking commitment for encodings
  vector<osuCrypto::block> commitsEncs;
  vector<pair<osuCrypto::block, osuCrypto::block>> decommitsEncs;
  map<unsigned int, unsigned int> ivA;
  ivA[j] = 2;
  PartyA::auxCommitEncsA(j, kappa, seedA, &ivA, encsSim, &commitsEncs, &decommitsEncs);

  int startIndex = 0;
  for(int i=0; i<GV::n1; i++) {
    CryptoPP::byte *commitEncASim0 = Util::blockToByte(commitsEncs.at(startIndex+2*i), Util::COMMIT_LENGTH);
    CryptoPP::byte *commitEncASim1 = Util::blockToByte(commitsEncs.at(startIndex+2*i+1), Util::COMMIT_LENGTH);
    CryptoPP::byte* commitEncA0 = Util::blockToByte(commitEncsA.at(startIndex+2*i), Util::COMMIT_LENGTH);
    CryptoPP::byte* commitEncA1 = Util::blockToByte(commitEncsA.at(startIndex+2*i+1), Util::COMMIT_LENGTH);

    if(memcmp(commitEncASim0, commitEncA0, Util::COMMIT_LENGTH) != 0 ||
       memcmp(commitEncASim1, commitEncA1, Util::COMMIT_LENGTH) != 0) {
      cout << "J: party A has cheated. Reason: wrong commitment for encodings" << endl;
      return true;
    }
  }
  cout << "J: correct commitments for encodings" << endl;

  //Checking commitment for cicuits
  GarbledCircuit *F = circuitInstance->exportCircuit();
  osuCrypto::block decommit = Util::byteToBlock(Util::randomByte(kappa, seedA, ivA[j]), kappa);
  CryptoPP::byte *commitASim = PartyA::commitCircuit(kappa, circuitInstance->getType(), F, decommit);
  if(memcmp(commitASim, Util::blockToByte(commitA, Util::COMMIT_LENGTH), Util::COMMIT_LENGTH) != 0) {
    cout << "J: party A has cheated. Reason: wrong commitment for circuits" << endl;
    return true;
  }
  cout << "J: correct commitments for circuits" << endl;

  cout << "J: everything ok" << endl;
  return false;
}

Judge::Judge(int k, CryptoPP::DSA::PublicKey publicKey, CircuitInterface* c){
  kappa = k;
  pk = publicKey;
  circuit = c;
}

Judge::~Judge(){
}
