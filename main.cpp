#include <iostream>
#include <string>
#include "CircuitInterface.h"
#include "CircuitReader.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Network/IOService.h"
#include "cryptoTools/Network/SocketAdapter.h"
#include "cryptlib.h"
#include "EvaluatorHalf.h"
#include "EvaluatorInterface.h"
#include "EvaluatorNormal.h"
#include "GarbledCircuit.h"
#include "HalfCircuit.h"
#include "NormalCircuit.h"
#include "libOTe/TwoChooseOne/KosOtExtReceiver.h"
#include "libOTe/TwoChooseOne/KosOtExtSender.h"
#include "PartyA.h"
#include "PartyB.h"
#include "Signature.h"
#include "SocketRecorder.h"
#include "Util.h"
using namespace std;

/*
  Runs a circuit from a file and checks that the amount of
  input is correct, the circuit can be evaluated and that
  the encoding can be decoded. The time for the evaluation
  is returned
*/
double runCircuit(CircuitInterface* circuit, EvaluatorInterface* evaluator, int kappa, string filename, string input) {
  try {
    CircuitReader cr = CircuitReader();
    pair<bool, vector<vector<CryptoPP::byte*>>> import = cr.import(circuit, filename);
    int inputGatesNr = cr.getInputGates();

    if(!import.first) {
      string msg = "Error! Could not import circuit";
      cout << msg << endl;
      throw msg;
    }

    clock_t start = clock();

    vector<vector<CryptoPP::byte*>> encodings = import.second;
    vector<CryptoPP::byte*> inputs;
    int i=0;
    for(char c : input) {
      if(i == inputGatesNr) {
        string msg = "Error! To many input gates. There are only "+to_string(inputGatesNr)+" input gates";
        cout << msg << endl;
        throw msg;
      }
      int b = (int) c - 48;
      inputs.push_back(encodings.at(i).at(b));
      i++;
    }

    if(i != inputGatesNr) {
        string msg = "Error! To few input gates. There should be "+to_string(inputGatesNr)+" input gates";
        cout << msg << endl;
        throw msg;
    }

    GarbledCircuit *F = circuit->exportCircuit();
    evaluator->giveCircuit(F);
    pair<bool, vector<CryptoPP::byte*>> evaluation = evaluator->evaluate(inputs);
    if(evaluation.first) {
      vector<CryptoPP::byte*> Z = evaluation.second;
      pair<bool, vector<bool>> decoded = evaluator->decode(Z);

      if(decoded.first) {
        cout << "output: ";
        for(bool b : decoded.second) {
          cout << b;
        }
        cout << endl;

        double duration = (clock()-start) / (double) CLOCKS_PER_SEC;
        return duration;
      } else {
        string msg = "Error! Could not decode the encoding";
        cout << msg << endl;
        throw msg;
      }
    } else {
      string msg = "Error! Could not evaluate circuit";
      cout << msg << endl;
      throw msg;
    }
  } catch (...) {
    return 0;
  }
}

/*
  Runs the circuit files
*/
void runCircuitFiles(int kappa) {
  CryptoPP::byte *seed = Util::randomByte(Util::SEED_LENGTH);
  string files[8] = {"adder64.txt", "divide64.txt", "udivide.txt", "mult64.txt", "mult2_64.txt", "sub64.txt", "neg64.txt", "zero_equal.txt"};

  double timeTotal0 = 0;
  double timeTotal1 = 0;

  for(string filename : files) {
    string i0 = "0101000000000000000000000000000000000000000000000000000000000000"; //10
    string i1 = "0100000000000000000000000000000000000000000000000000000000000000"; //2

    cout << filename << endl;
    cout << "Input: " << i0;
    string input = "";
    input += i0;
    if(filename.compare("neg64.txt") != 0 && filename.compare("zero_equal.txt") != 0) {
      input += i1;
      cout << " | " << i1;
    }
    cout << endl;

    CircuitInterface *circuitN = new NormalCircuit(kappa, seed);
    CircuitInterface *circuitH = new HalfCircuit(kappa, seed);
    EvaluatorInterface *evalN = new EvaluatorNormal();
    EvaluatorInterface *evalH = new EvaluatorHalf();

    double time0 = runCircuit(circuitN, evalN, kappa, filename, input);
    double time1 = runCircuit(circuitH, evalH, kappa, filename, input);
    timeTotal0 += time0;
    timeTotal1 += time1;

    cout << "Time: " << time0 << " ("+circuitN->toString()+"), " << time1 << " ("+circuitH->toString()+")" << endl;
    cout << endl;
  }

  cout << "Time total: " << timeTotal0 << " (normal), " << timeTotal1 << " (half)" << endl;
}

void startProtocol(int kappa, int lambda, int x, int y) {
  //Network
  osuCrypto::IOService ios(16);
  osuCrypto::Channel chlSer = osuCrypto::Session(ios, GV::ADDRESS, osuCrypto::SessionMode::Server).addChannel();
  osuCrypto::Channel chlCli = osuCrypto::Session(ios, GV::ADDRESS, osuCrypto::SessionMode::Client).addChannel();
  osuCrypto::SocketInterface *siSer = new SocketRecorder(chlSer);
  osuCrypto::SocketInterface *siCli= new SocketRecorder(chlCli);
  SocketRecorder *socketRecorderServer = (SocketRecorder*) siSer;
  SocketRecorder *socketRecorderClient = (SocketRecorder*) siCli;
  osuCrypto::Channel chlSerOT(ios, siSer);
  osuCrypto::Channel chlCliOT(ios, siCli);
  chlCli.waitForConnection();
  chlCliOT.waitForConnection();

  //Digital Signature
  CryptoPP::DSA::PrivateKey sk = Signature::generateRandomPrivateKey(1024);
  CryptoPP::DSA::PublicKey pk = Signature::generatePublicKey(sk);

  //Circuit
  CryptoPP::byte *unimportantSeed = Util::randomByte(Util::SEED_LENGTH);
  CircuitInterface *circuit;
  EvaluatorInterface *evaluator;

  if(Util::randomInt(0, 1)) {
    cout << "Half - x: " << x << ", y: " << y << endl;
    circuit = new HalfCircuit(kappa, unimportantSeed);
    evaluator = new EvaluatorHalf();
  } else {
    cout << "Normal - x: " << x << ", y: " << y << endl;
    circuit = new NormalCircuit(kappa, unimportantSeed);
    evaluator = new EvaluatorNormal();
  }

  bool b0;
  bool b1;
  auto threadA = thread([&]() {
    PartyA partyA = PartyA(x, sk, pk, kappa, lambda, chlSerOT, socketRecorderServer, circuit);
    b0 = partyA.startProtocol();
  });
  auto threadB = thread([&]() {
    PartyB partyB = PartyB(y, pk, kappa, lambda, chlCliOT, socketRecorderClient, circuit, evaluator, &ios);
    b1 = partyB.startProtocol();
  });

  threadA.join();
  threadB.join();
  chlCliOT.close();
  chlSerOT.close();
  chlCli.close();
  chlSer.close();
  ios.stop();

  if(b0 && b1) {
    cout << "Success" << endl;
  } else {
    cout << "Fail" << endl;
  }
}

void test(int kappa) {
  //Network
  osuCrypto::IOService ios(16);
  osuCrypto::Channel chlSer = osuCrypto::Session(ios, GV::ADDRESS, osuCrypto::SessionMode::Server).addChannel();
  osuCrypto::Channel chlCli = osuCrypto::Session(ios, GV::ADDRESS, osuCrypto::SessionMode::Client).addChannel();
  osuCrypto::SocketInterface *siSer = new SocketRecorder(chlSer);
  osuCrypto::SocketInterface *siCli= new SocketRecorder(chlCli);
  SocketRecorder *socketRecorderServer = (SocketRecorder*) siSer;
  SocketRecorder *socketRecorderClient = (SocketRecorder*) siCli;
  osuCrypto::Channel recSer(ios, siSer);
  osuCrypto::Channel recCli(ios, siCli);
  chlCli.waitForConnection();
  recCli.waitForConnection();

  CryptoPP::byte *seed = Util::randomByte(kappa);
  CryptoPP::byte *witness = Util::randomByte(kappa);
  socketRecorderClient->storeIn("ot1");
  socketRecorderServer->storeIn("ot1");

  auto t1 = thread([&]() {
    osuCrypto::KosOtExtReceiver recver;
    Util::setBaseCli(&recver, recCli, seed, kappa);
    osuCrypto::PRNG prng(osuCrypto::toBlock(5));
    osuCrypto::BitVector choices(1);
    choices[0] = 0;
    vector<osuCrypto::block> msg(1);
    recver.receiveChosen(choices, msg, prng, recCli);
    Util::printBlockInBits(msg[0], 16);
  });

  auto t2 = thread([&]() {
    osuCrypto::KosOtExtSender sender;
    osuCrypto::PRNG prng(osuCrypto::toBlock(5));

    vector<array<osuCrypto::block, 2>> sendMessages(1);
    Util::setBaseSer(&sender, recSer);
    sendMessages[0] = {Util::byteToBlock(seed, kappa), Util::byteToBlock(witness, kappa)};

    sender.sendChosen(sendMessages, prng, recSer);
  });

  t1.join();
  t2.join();

  socketRecorderServer->storeIn("ot2");
  socketRecorderClient->storeIn("ot2");

  auto t3 = thread([&]() {
    osuCrypto::KosOtExtReceiver recver;
    Util::setBaseCli(&recver, recCli, seed, kappa);
    osuCrypto::PRNG prng(osuCrypto::toBlock(5));
    osuCrypto::BitVector choices(1);
    choices[0] = 0;
    vector<osuCrypto::block> msg(1);
    recver.receiveChosen(choices, msg, prng, recCli);
    Util::printBlockInBits(msg[0], 16);
  });

  auto t4 = thread([&]() {
    //ot from transscripts
    vector<pair<int, CryptoPP::byte*>> sentData = socketRecorderServer->getSentCat("ot1");
    vector<pair<int, CryptoPP::byte*>> recvData = socketRecorderServer->getRecvCat("ot1");

    array<int, 4> b0;
    recSer.recv(b0);

    array<int, 5> b1;
    recSer.recv(b1);

    array<int, 4096> b2;
    recSer.recv(b2);

    recSer.send(sentData.at(1).second, sentData.at(1).first);

    array<int, 4> b3;
    recSer.recv(b3);

    array<int, 12> b4;
    recSer.recv(b4);

    recSer.send(sentData.at(3).second, sentData.at(3).first);
  });

  t3.join();
  t4.join();

  vector<pair<int, CryptoPP::byte*>> dataRecv1 = socketRecorderServer->getRecvCat("ot1");
  vector<pair<int, CryptoPP::byte*>> dataRecv2 = socketRecorderServer->getRecvCat("ot2");

  if(dataRecv1.size() != dataRecv2.size()) {
    cout << "not same size" << endl;
  }

  for(int i=0; i<dataRecv1.size(); i++) {
    pair<int, CryptoPP::byte*> p1 = dataRecv1.at(i);
    pair<int, CryptoPP::byte*> p2 = dataRecv2.at(i);
    if(memcmp(p1.second, p2.second, p2.first) != 0) {
      cout << "not equal (" << i << "/" << dataRecv1.size() << ")" << endl;
    }
  }
}

int main() {
  cout << "covert start" << endl;

  int kappa = 16; //they use 16 bytes, 16*8=128 bits
  int lambda = 8;
  int x = 5;
  int y = 4;

  //runCircuitFiles(kappa);
  startProtocol(kappa, lambda, x, y);
  //test(kappa);

  cout << "covert end" << endl;
  return 0;
}
