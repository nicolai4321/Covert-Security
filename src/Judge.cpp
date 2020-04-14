#include "Judge.h"
using namespace std;

bool Judge::accuse(int j, CryptoPP::SecByteBlock signature, size_t signatureLength, CryptoPP::byte* seedB, osuCrypto::block decommitB,
                   osuCrypto::Commit commitA, vector<osuCrypto::Commit> commitEncsA,
                   vector<pair<int, unsigned char*>> *transcriptSent1,
                   vector<pair<int, unsigned char*>> *transcriptRecv1,
                   vector<pair<int, unsigned char*>> *transcriptSent2,
                   vector<pair<int, unsigned char*>> *transcriptRecv2) {
  cout << "Judge called: " << j << endl;
  osuCrypto::Commit commitB = Util::commit(Util::byteToBlock(seedB, kappa), decommitB);

  pair<CryptoPP::byte*, int> signatureMsg = PartyA::constructSignatureByte(j, kappa, &commitA, &commitB, &commitEncsA, transcriptSent1,
                                                         transcriptRecv1, transcriptSent2, transcriptRecv2);
  bool correctSignature = Signature::verify(pk, signatureMsg.first, signatureMsg.second, signature, signatureLength);
  delete signatureMsg.first;
  if(!correctSignature) {
    cout << "J: The signature is not correct" << endl;
    return false;
  }
  cout << "Judge: correct signature" << endl;

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
  osuCrypto::KosOtExtReceiver recver;
  osuCrypto::KosOtExtSender sender;
  CryptoPP::byte seedA[kappa];

  chlCli.waitForConnection();
  recCli.waitForConnection();

  socketRecorderServer->storeIn("ot1");
  socketRecorderClient->storeIn("ot1");
  auto threadCli = thread([&]() {
    int iv = 0;
    CryptoPP::byte seedInput[kappa];
    Util::randomByte(seedInput, kappa, seedB, kappa, iv);

    osuCrypto::BitVector choices(1);
    choices[0] = 0;
    vector<osuCrypto::block> seedAblock(1);
    osuCrypto::PRNG prng(Util::byteToBlock(seedInput, kappa));
    recver.genBaseOts(prng, recCli);
    recver.receiveChosen(choices, seedAblock, prng, recCli);
    Util::blockToByte(seedAblock[0], kappa, seedA);
  });

  //This thread below does the OT with the transcript
  //that is signed. The received messages is not stored here
  //since they are stored in the socket recorder object.
  auto threadSer = thread([&]() {
    //base ots
    array<int, 8> b0;
    recSer.recv(b0);

    for(int i=0; i<32; i++) {
      int index = 2*i+1;
      recSer.send(transcriptSent1->at(index).second, transcriptSent1->at(index).first);
    }

    array<int, 4> b1;
    recSer.recv(b1);

    //ot
    array<int, 5> b2;
    recSer.recv(b2);

    array<int, 4096> b3;
    recSer.recv(b3);

    recSer.send(transcriptSent1->at(65).second, transcriptSent1->at(65).first);

    array<int, 4> b4;
    recSer.recv(b4);

    array<int, 12> b5;
    recSer.recv(b5);

    recSer.send(transcriptSent1->at(67).second, transcriptSent1->at(67).first);
  });

  threadSer.join();
  threadCli.join();

  //Checks that the received messages have same length
  vector<pair<int, CryptoPP::byte*>> transcriptSimRecv1;
  socketRecorderServer->getRecvCat("ot1", &transcriptSimRecv1);

  if(transcriptSimRecv1.size() != transcriptRecv1->size()) {
    cout << "J: The transcripts have incorrect size for the 1st ot!" << endl;
    return false;
  }

  //Checks that the received messages are identical
  for(int i=0; i<transcriptSimRecv1.size(); i++) {
    pair<int, CryptoPP::byte*> p0 = transcriptSimRecv1.at(i);
    pair<int, CryptoPP::byte*> p1 = transcriptRecv1->at(i);
    if(memcmp(p0.second, p1.second, p1.first) != 0) {
      cout << "J: The transcripts are not identical for the 1st ot!" << endl;
      return false;
    }
  }
  cout << "J: correct transcripts for 1st ot" << endl;

  //Simulated garbling
  CircuitInterface *circuitInstance = circuit->createInstance(kappa, seedA);
  CircuitReader cr = CircuitReader();
  cr.setReverseInput(true);
  pair<bool, vector<vector<CryptoPP::byte*>>> import = cr.import(circuitInstance, GV::filename);
  if(!import.first) {throw runtime_error("J: Error! Could not import circuit");}
  vector<vector<CryptoPP::byte*>> encsSim = import.second;

  //Checking commitment for encodings
  vector<osuCrypto::Commit> commitsEncs;
  vector<pair<osuCrypto::block, osuCrypto::block>> decommitsEncs;
  map<unsigned int, unsigned int> ivA;
  ivA[j] = 2;
  PartyA::auxCommitEncsA(j, kappa, seedA, &ivA, encsSim, &commitsEncs, &decommitsEncs);

  int startIndex = 0;
  for(int i=0; i<GV::n1; i++) {
    osuCrypto::Commit commitEncASim0 = commitsEncs.at(startIndex+2*i);
    osuCrypto::Commit commitEncASim1 = commitsEncs.at(startIndex+2*i+1);
    osuCrypto::Commit commitEncA0 = commitEncsA.at(startIndex+2*i);
    osuCrypto::Commit commitEncA1 = commitEncsA.at(startIndex+2*i+1);

    if(commitEncASim0.size() != commitEncA0.size() || commitEncASim1.size() != commitEncA1.size()) {
      cout << "J: party A has cheated. Reason: wrong commitment size for encodings" << endl;
      return true;
    }

    if(memcmp(commitEncASim0.data(), commitEncA0.data(), commitEncASim0.size()) != 0 ||
       memcmp(commitEncASim1.data(), commitEncA1.data(), commitEncASim1.size()) != 0) {
      cout << "J: party A has cheated. Reason: wrong commitment for encodings" << endl;
      return true;
    }
  }
  cout << "J: correct commitments for encodings" << endl;

  //Checking commitment for cicuits
  GarbledCircuit *F = new GarbledCircuit();
  circuitInstance->exportCircuit(F);
  CryptoPP::byte decom[kappa];
  Util::randomByte(decom, kappa, seedA, kappa, ivA[j]);

  osuCrypto::block decommit = Util::byteToBlock(decom, kappa);
  osuCrypto::Commit commitASim = PartyA::commitCircuit(kappa, circuitInstance->getType(), F, decommit);

  if(commitASim.size() != commitA.size()) {
    cout << "J: party A has cheated. Reason: wrong commitment size for circuits" << endl;
    return true;
  }

  if(memcmp(commitASim.data(), commitA.data(), commitASim.size()) != 0) {
    cout << "J: party A has cheated. Reason: wrong commitment for circuits" << endl;
    return true;
  }
  cout << "J: correct commitments for circuits" << endl;

  socketRecorderServer->storeIn("ot2");
  socketRecorderClient->storeIn("ot2");

  auto threadCli2 = thread([&]() {
    int iv = 1;

    osuCrypto::BitVector choices(GV::n2);
    for(int i=0; i<GV::n2; i++) {
      choices[i] = 0;
    }

    vector<osuCrypto::block> recv(GV::n2);
    CryptoPP::byte seedInput[kappa];
    Util::randomByte(seedInput, kappa, seedB, kappa, iv);
    osuCrypto::PRNG prng(Util::byteToBlock(seedInput, kappa));
    recver.genBaseOts(prng, recCli);
    recver.receiveChosen(choices, recv, prng, recCli);
  });

  auto threadSer2 = thread([&]() {
    int iv = 1;
    vector<array<block, 2>> data(GV::n2);
    for(int i=0; i<GV::n2; i++) {
      osuCrypto::block enc0 = Util::byteToBlock(encsSim.at(GV::n1+i).at(0), kappa);
      osuCrypto::block enc1 = Util::byteToBlock(encsSim.at(GV::n1+i).at(1), kappa);
      data[i] = {enc0, enc1};
    }

    CryptoPP::byte seedInput[kappa];
    Util::randomByte(seedInput, kappa, seedA, kappa, iv);
    osuCrypto::PRNG prng(Util::byteToBlock(seedInput, kappa));
    sender.genBaseOts(prng, recSer);
    sender.sendChosen(data, prng, recSer);
  });

  threadCli2.join();
  threadSer2.join();

  vector<pair<int, CryptoPP::byte*>> transcriptSimSent2;
  vector<pair<int, CryptoPP::byte*>> transcriptSimRecv2;
  socketRecorderServer->getSentCat("ot2", &transcriptSimSent2);
  socketRecorderServer->getRecvCat("ot2", &transcriptSimRecv2);

  //base ot
  if(memcmp(transcriptSimRecv2.at(0).second, transcriptRecv2->at(0).second, 4) != 0) return 0;
  if(memcmp(transcriptSimRecv2.at(1).second, transcriptRecv2->at(1).second, 32) != 0) return 0;

  for(int i=0; i<32; i++) {
    if(memcmp(transcriptSimSent2.at(2*i).second, transcriptSent2->at(2*i).second, 4) != 0) return 1;
    if(memcmp(transcriptSimSent2.at(2*i+1).second, transcriptSent2->at(2*i+1).second, 128) != 0) return 1;
  }

  if(memcmp(transcriptSimRecv2.at(2).second, transcriptRecv2->at(2).second, 4) != 0) return 0;
  if(memcmp(transcriptSimRecv2.at(3).second, transcriptRecv2->at(3).second, 16) != 0) return 0;

  //ot
  if(memcmp(transcriptSimRecv2.at(4).second, transcriptRecv2->at(4).second, 4) != 0) return 0;
  if(memcmp(transcriptSimRecv2.at(5).second, transcriptRecv2->at(5).second, 20) != 0) return 0;
  if(memcmp(transcriptSimRecv2.at(6).second, transcriptRecv2->at(6).second, 4) != 0) return 0;
  if(memcmp(transcriptSimRecv2.at(7).second, transcriptRecv2->at(7).second, 16384) != 0) return 0;

  if(memcmp(transcriptSimSent2.at(64).second, transcriptSent2->at(64).second, 4) != 0) return 1;
  if(memcmp(transcriptSimSent2.at(65).second, transcriptSent2->at(65).second, 16) != 0) return 1;

  if(memcmp(transcriptSimRecv2.at(8).second, transcriptRecv2->at(8).second, 4) != 0) return 0;
  if(memcmp(transcriptSimRecv2.at(9).second, transcriptRecv2->at(9).second, 16) != 0) return 0;
  if(memcmp(transcriptSimRecv2.at(10).second, transcriptRecv2->at(10).second, 4) != 0) return 0;
  if(memcmp(transcriptSimRecv2.at(11).second, transcriptRecv2->at(11).second, 48) != 0) return 0;

  if(memcmp(transcriptSimSent2.at(66).second, transcriptSent2->at(66).second, 4) != 0) return 1;
  if(memcmp(transcriptSimSent2.at(67).second, transcriptSent2->at(67).second, 96) != 0) return 1;

  recCli.close();
  recSer.close();
  chlCli.close();
  chlSer.close();
  ios.stop();
  delete F;

  cout << "J: correct transcripts for 2nd ot" << endl;
  return false;
}

Judge::Judge(int k, CryptoPP::RSA::PublicKey publicKey, CircuitInterface* c){
  kappa = k;
  pk = publicKey;
  circuit = c;
}

Judge::~Judge(){
}
