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
  int port = 1212;
  string ip = "localhost";
  string ipAddress = ip+":"+to_string(port);
  osuCrypto::IOService ios;
  osuCrypto::Channel serverChl = osuCrypto::Session(ios, ipAddress, osuCrypto::SessionMode::Server).addChannel();
  osuCrypto::Channel clientChl = osuCrypto::Session(ios, ipAddress, osuCrypto::SessionMode::Client).addChannel();
  clientChl.waitForConnection();

  //Etc.
  CryptoPP::byte *seed = Util::randomByte(Util::SEED_LENGTH);
  CircuitInterface *circuit;
  EvaluatorInterface *evaluator;

  if(Util::randomInt(0, 1)) {
    cout << "Half - x: " << x << ", y: " << y << endl;
    circuit = new HalfCircuit(kappa, seed);
    evaluator = new EvaluatorHalf();
  } else {
    cout << "Normal - x: " << x << ", y: " << y << endl;
    circuit = new NormalCircuit(kappa, seed);
    evaluator = new EvaluatorNormal();
  }

  bool b0;
  bool b1;
  auto threadA = thread([&]() {
    PartyA partyA = PartyA(x, kappa, lambda, serverChl, circuit);
    b0 = partyA.startProtocol();
  });
  auto threadB = thread([&]() {
    PartyB partyB = PartyB(y, kappa, lambda, clientChl, circuit, evaluator);
    b1 = partyB.startProtocol();
  });

  threadA.join();
  threadB.join();
  serverChl.close();
  clientChl.close();
  ios.stop();


  if(b0 && b1) {
    cout << "Success" << endl;
  } else {
    cout << "Fail" << endl;
  }
}

void nextOT(osuCrypto::Channel chl0, osuCrypto::Channel chl1, CryptoPP::byte* seed, int n, osuCrypto::BitVector choices, vector<array<osuCrypto::block, 2>> data) {
  cout << "OT START" << endl;
  //Base OTs
  vector<osuCrypto::block> baseRecv(128);
  vector<array<osuCrypto::block, 2>> baseSend(128);
  osuCrypto::BitVector baseChoice(128);

  for(osuCrypto::u64 i=0; i<128; ++i) {
    baseSend[i][0] = osuCrypto::toBlock(i);
    baseSend[i][1] = osuCrypto::toBlock(i);
    baseRecv[i] = baseSend[i][baseChoice[i]];
  }

  //RECEIVER
  auto recverThread = thread([&]() {
    osuCrypto::PRNG prng0(Util::byteToBlock(seed, 16), 16);
    vector<osuCrypto::block> dest0(n);
    osuCrypto::KosOtExtReceiver recver;
    recver.setBaseOts(baseSend, prng0, chl0);
    recver.receiveChosen(choices, dest0, prng0, chl0);

    cout << "OUTPUT: ";
    for(osuCrypto::block b : dest0) {
      cout << b[0] << ",";
    }
  });

  //SENDER
  auto senderThread = thread([&]() {
    osuCrypto::PRNG prng1(Util::byteToBlock(seed, 16), 16);
    osuCrypto::KosOtExtSender sender;
    sender.setBaseOts(baseRecv, baseChoice, chl1);
    sender.sendChosen(data, prng1, chl1);
  });

  recverThread.join();
  senderThread.join();
  cout << "OT DONE" << endl;
}

/*
  Returns true if the the transscripts from two channels are equal
*/
bool checkTransscripts(vector<pair<int, CryptoPP::byte*>> dataRecv0,
                       vector<pair<int, CryptoPP::byte*>> dataSent0,
                       vector<pair<int, CryptoPP::byte*>> dataRecv1,
                       vector<pair<int, CryptoPP::byte*>> dataSent1) {

  //Checking the length of the messages
  if(dataRecv0.size() != dataRecv1.size()) return false;
  if(dataSent0.size() != dataSent1.size()) return false;

  //Checking the received messages
  for(int i=0; i<dataRecv0.size(); i++) {
    int siz0 = dataRecv0.at(i).first;
    int siz1 = dataRecv1.at(i).first;
    if(siz0 != siz1) return false;

    CryptoPP::byte *b0 = dataRecv0.at(i).second;
    CryptoPP::byte *b1 = dataRecv1.at(i).second;
    if(memcmp(b0, b1, siz0) != 0) return false;
  }

  //Checking the sent messages
  for(int i=0; i<dataSent0.size(); i++) {
    int siz0 = dataSent0.at(i).first;
    int siz1 = dataSent1.at(i).first;
    if(siz0 != siz1) return false;

    CryptoPP::byte *b0 = dataSent0.at(i).second;
    CryptoPP::byte *b1 = dataSent1.at(i).second;
    if(memcmp(b0, b1, siz0) != 0) return false;
  }

  return true;
}

void runEqualTest() {
  int port = 1212;
  string server = "localhost";
  string ipadd = server + ":" + to_string(port);

  typedef Channel YourSocketType2;
  osuCrypto::IOService ios;
  osuCrypto::Channel chlSer0 = osuCrypto::Session(ios, ipadd, osuCrypto::SessionMode::Server).addChannel();
  osuCrypto::Channel chlCli0 = osuCrypto::Session(ios, ipadd, osuCrypto::SessionMode::Client).addChannel();
  osuCrypto::Channel chlSer1 = osuCrypto::Session(ios, ipadd, osuCrypto::SessionMode::Server).addChannel();
  osuCrypto::Channel chlCli1 = osuCrypto::Session(ios, ipadd, osuCrypto::SessionMode::Client).addChannel();
  osuCrypto::SocketInterface *siSerRec0 = new SocketRecorder(chlSer0);
  osuCrypto::SocketInterface *siCliRec0 = new SocketRecorder(chlCli0);
  osuCrypto::SocketInterface *siSerRec1 = new SocketRecorder(chlSer1);
  osuCrypto::SocketInterface *siCliRec1 = new SocketRecorder(chlCli1);
  Channel chlSerRec0(ios, siSerRec0);
  Channel chlCliRec0(ios, siCliRec0);
  Channel chlSerRec1(ios, siSerRec1);
  Channel chlCliRec1(ios, siCliRec1);

  //OT
  int n = 2;

  CryptoPP::byte *seed0 = new CryptoPP::byte[16];
  memset(seed0, 0x50, 16);

  CryptoPP::byte *seed1 = new CryptoPP::byte[16];
  memset(seed1, 0x50, 16);

  osuCrypto::BitVector choices0(2);
  choices0[0] = 1;
  choices0[1] = 0;

  osuCrypto::BitVector choices1(2);
  choices1[0] = 1;
  choices1[1] = 0;

  vector<array<osuCrypto::block, 2>> data0(n);
  data0[0] = {osuCrypto::toBlock(432), osuCrypto::toBlock(5)};
  data0[1] = {osuCrypto::toBlock(5), osuCrypto::toBlock(4394)};

  vector<array<osuCrypto::block, 2>> data1(n);
  data1[0] = {osuCrypto::toBlock(432), osuCrypto::toBlock(5)};
  data1[1] = {osuCrypto::toBlock(5), osuCrypto::toBlock(4394)};

  nextOT(chlSerRec0, chlCliRec0, seed0, n, choices0, data0);
  nextOT(chlSerRec1, chlCliRec1, seed1, n, choices1, data1);

  //CHECKING
  SocketRecorder *socSerRec0 = (SocketRecorder*) siSerRec0;
  SocketRecorder *socCliRec0 = (SocketRecorder*) siCliRec0;
  SocketRecorder *socSerRec1 = (SocketRecorder*) siSerRec1;
  SocketRecorder *socCliRec1 = (SocketRecorder*) siCliRec1;

  //CHECK DATA!
  cout << "Servers: " << checkTransscripts(socSerRec0->getDataRecv(), socSerRec0->getDataSent(), socSerRec1->getDataRecv(), socSerRec1->getDataSent()) <<  endl;
  cout << "Clients: " << checkTransscripts(socCliRec0->getDataRecv(), socCliRec0->getDataSent(), socCliRec1->getDataRecv(), socCliRec1->getDataSent()) <<  endl;
}

int main() {
  cout << "covert start" << endl;
  int kappa = 16; //they use 16 bytes, 16*8=128 bits
  int lambda = 8;
  int x = 5;
  int y = 2;

  //runCircuitFiles(kappa);
  //startProtocol(kappa, lambda, x, y);
  runEqualTest();

  cout << "covert end" << endl;
  return 0;
}
