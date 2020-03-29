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

  auto threadCli = thread([&]() {
    osuCrypto::KosOtExtReceiver recver;
    Util::setBaseCli(&recver, recCli, seedB, kappa);

    int iv = 0;
    CryptoPP::byte *seedInput = Util::randomByte(kappa, seedB, iv);
    osuCrypto::PRNG prng(Util::byteToBlock(seedInput, kappa));
    osuCrypto::BitVector choices(1);
    choices[0] = 0;
    vector<osuCrypto::block> seedA(1);
    recver.receiveChosen(choices, seedA, prng, recCli);
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

  recCli.close();
  recSer.close();
  chlCli.close();
  chlSer.close();
  ios.stop();

  return true;
}

Judge::Judge(int k, CryptoPP::DSA::PublicKey publicKey){
  kappa = k;
  pk = publicKey;
}

Judge::~Judge(){
}
