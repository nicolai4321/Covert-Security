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
    PartyB partyB = PartyB(y, pk, kappa, lambda, chlCliOT, socketRecorderClient, circuit, evaluator);
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

void nextOT(osuCrypto::KosOtExtSender* sender, osuCrypto::KosOtExtReceiver* recver, osuCrypto::Channel chlSer, osuCrypto::Channel chlCli, CryptoPP::byte* seedSer, CryptoPP::byte* seedCli, int n, osuCrypto::BitVector choices, vector<array<osuCrypto::block, 2>> data) {
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
    osuCrypto::PRNG prng0(Util::byteToBlock(seedCli, 16), 16);
    vector<osuCrypto::block> dest0(n);
    recver->setBaseOts(baseSend, prng0, chlCli);
    recver->receiveChosen(choices, dest0, prng0, chlCli);

    cout << "OUTPUT: ";
    for(osuCrypto::block b : dest0) {
      cout << b[0] << ",";
    }
    cout << endl;
  });

  //SENDER
  auto senderThread = thread([&]() {
    osuCrypto::PRNG prng1(Util::byteToBlock(seedSer, 16), 16);
    sender->setBaseOts(baseRecv, baseChoice, chlSer);
    sender->sendChosen(data, prng1, chlSer);
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
  if(dataRecv0.size() == 0) return false;
  if(dataRecv1.size() == 0) return false;
  if(dataSent0.size() == 0) return false;
  if(dataSent1.size() == 0) return false;
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

void nextSer(osuCrypto::KosOtExtSender* sender, osuCrypto::Channel chlSer, SocketRecorder* socRec, vector<CryptoPP::byte*> seedsA, int lambda, vector<vector<osuCrypto::block>> data) {
  for(int j=0; j<lambda; j++) {
    Util::setBaseSer(sender, chlSer);
    socRec->storeIn("ot2"+to_string(j));
    vector<array<osuCrypto::block, 2>> dataOT(1);
    dataOT[0] = {data.at(j).at(0), data.at(j).at(1)};
    osuCrypto::PRNG prng(Util::byteToBlock(seedsA.at(j), 16), 16);
    sender->sendChosen(dataOT, prng, chlSer);
  }
}

void nextCli(osuCrypto::KosOtExtReceiver* recver, osuCrypto::Channel chlCli, SocketRecorder* socRec, vector<CryptoPP::byte*> seedsB, int lambda, int siz, vector<int> choices) {
  for(int j=0; j<lambda; j++) {
    socRec->storeIn("ot2"+to_string(j));
    Util::setBaseCli(recver, chlCli, seedsB.at(j));
    osuCrypto::BitVector choice(1);
    choice[0] = choices.at(j);
    osuCrypto::PRNG prng(Util::byteToBlock(seedsB.at(j), 16), 16);
    vector<osuCrypto::block> dest(1);
    recver->receiveChosen(choice, dest, prng, chlCli);

    cout << "OUTPUT: ";
    for(osuCrypto::block b : dest) {
      cout << b[0] << ",";
    }
    cout << endl;
  }
}

void runEqualTest(int kappa) {
  osuCrypto::IOService ios;
  osuCrypto::IOService iosSim;
  osuCrypto::Channel chlSer = osuCrypto::Session(ios, GV::ADDRESS, osuCrypto::SessionMode::Server).addChannel();
  osuCrypto::Channel chlCli = osuCrypto::Session(ios, GV::ADDRESS, osuCrypto::SessionMode::Client).addChannel();
  osuCrypto::Channel chlSerSim = osuCrypto::Session(iosSim, GV::ADDRESS_SIM, osuCrypto::SessionMode::Server).addChannel();
  osuCrypto::Channel chlCliSim = osuCrypto::Session(iosSim, GV::ADDRESS_SIM, osuCrypto::SessionMode::Client).addChannel();
  osuCrypto::SocketInterface *siSer = new SocketRecorder(chlSer);
  osuCrypto::SocketInterface *siCli = new SocketRecorder(chlCli);
  osuCrypto::SocketInterface *siSerSim = new SocketRecorder(chlSerSim);
  osuCrypto::SocketInterface *siCliSim = new SocketRecorder(chlCliSim);
  Channel recSer(ios, siSer);
  Channel recCli(ios, siCli);
  Channel recSerSim(ios, siSerSim);
  Channel recCliSim(ios, siCliSim);
  SocketRecorder *socSer = (SocketRecorder*) siSer;
  SocketRecorder *socCli = (SocketRecorder*) siCli;
  SocketRecorder *socSerSim = (SocketRecorder*) siSerSim;
  SocketRecorder *socCliSim = (SocketRecorder*) siCliSim;

  int lambda = 8;
  int siz = 8;
  int y = 2;
  int gamma = 2;

  vector<CryptoPP::byte*> seedsA;
  vector<CryptoPP::byte*> seedsB;
  vector<CryptoPP::byte*> seedsAsim;
  vector<CryptoPP::byte*> seedsBsim;
  map<unsigned int, unsigned int> ivA;
  map<unsigned int, unsigned int> ivB;
  map<unsigned int, unsigned int> ivAsim;
  map<unsigned int, unsigned int> ivBsim;
  for(int j=0; j<lambda; j++) {
    CryptoPP::byte *seedSer = new CryptoPP::byte[kappa];
    memset(seedSer, 0x40, kappa);
    seedsA.push_back(seedSer);

    CryptoPP::byte *seedCli = new CryptoPP::byte[kappa];
    memset(seedCli, 0x50, kappa);
    seedsB.push_back(seedCli);

    CryptoPP::byte *seedSerSim = new CryptoPP::byte[kappa];
    memset(seedSerSim, 0x40, kappa);
    seedsAsim.push_back(seedSerSim);

    CryptoPP::byte *seedCliSim = new CryptoPP::byte[kappa];
    memset(seedCliSim, 0x50, kappa);
    seedsBsim.push_back(seedCliSim);

    ivA[j] = 0;
    ivB[j] = 0;
    ivAsim[j] = 0;
    ivBsim[j] = 0;
  }

  osuCrypto::KosOtExtSender sender;
  osuCrypto::KosOtExtReceiver recver;

  vector<int> choices;
  choices.push_back(0);
  choices.push_back(0);
  choices.push_back(0);
  choices.push_back(0);
  choices.push_back(1);
  choices.push_back(1);
  choices.push_back(1);
  choices.push_back(1);

  vector<vector<osuCrypto::block>> data;
  data.push_back({osuCrypto::toBlock(5) ,osuCrypto::toBlock(53)});
  data.push_back({osuCrypto::toBlock(5) ,osuCrypto::toBlock(53)});
  data.push_back({osuCrypto::toBlock(5) ,osuCrypto::toBlock(53)});
  data.push_back({osuCrypto::toBlock(5) ,osuCrypto::toBlock(53)});
  data.push_back({osuCrypto::toBlock(53) ,osuCrypto::toBlock(5)});
  data.push_back({osuCrypto::toBlock(53) ,osuCrypto::toBlock(5)});
  data.push_back({osuCrypto::toBlock(53) ,osuCrypto::toBlock(5)});
  data.push_back({osuCrypto::toBlock(53) ,osuCrypto::toBlock(5)});

  //first ot
  vector<array<osuCrypto::block, 2>> data1(2);
  data1[0] = {osuCrypto::toBlock(23), osuCrypto::toBlock(5)};
  data1[1] = {osuCrypto::toBlock(23), osuCrypto::toBlock(5)};

  osuCrypto::BitVector choices1(2);
  choices1[0] = 1;
  choices1[1] = 1;

  nextOT(&sender, &recver, recSer, recCli, seedsA.at(0), seedsB.at(0), 2, choices1, data1);

  auto threadSer = thread([&]() {
    nextSer(&sender, recSer, socSer, seedsA, lambda, data);

    //map<int, vector<vector<CryptoPP::byte*>>> encs;
    //PartyA::otEncs(&sender, lambda, kappa, recSer, socSer, encs, seedsA, &ivA);
  });
  auto threadCli = thread([&]() {
    nextCli(&recver, recCli, socCli, seedsB, lambda, siz, choices);

    //PartyB::otEncodingsB(&recver, y, lambda, kappa, gamma, recCli, socCli, seedsB, &ivB);
  });
  threadSer.join();
  threadCli.join();

  vector<int> choicesSim;
  choicesSim.push_back(0);
  choicesSim.push_back(0);
  choicesSim.push_back(0);
  choicesSim.push_back(0);
  choicesSim.push_back(1);
  choicesSim.push_back(1);
  choicesSim.push_back(1);
  choicesSim.push_back(1);

  vector<vector<osuCrypto::block>> dataSim;
  dataSim.push_back({osuCrypto::toBlock(5) ,osuCrypto::toBlock(53)});
  dataSim.push_back({osuCrypto::toBlock(5) ,osuCrypto::toBlock(53)});
  dataSim.push_back({osuCrypto::toBlock(5) ,osuCrypto::toBlock(321)}); //unknown
  dataSim.push_back({osuCrypto::toBlock(5) ,osuCrypto::toBlock(53)});
  dataSim.push_back({osuCrypto::toBlock(53) ,osuCrypto::toBlock(5)});
  dataSim.push_back({osuCrypto::toBlock(53) ,osuCrypto::toBlock(5)});
  dataSim.push_back({osuCrypto::toBlock(53) ,osuCrypto::toBlock(5)});
  dataSim.push_back({osuCrypto::toBlock(53) ,osuCrypto::toBlock(5)});

  auto threadSerSim = thread([&]() {
    nextSer(&sender, recSerSim, socSerSim, seedsAsim, lambda, dataSim);

    //map<int, vector<vector<CryptoPP::byte*>>> encs;
    //PartyA::otEncs(&sender, lambda, kappa, recSerSim, socSerSim, encs, seedsA, &ivAsim);
  });
  auto threadCliSim = thread([&]() {
    nextCli(&recver, recCliSim, socCliSim, seedsBsim, lambda, siz, choicesSim);

    //PartyB::otEncodingsB(&recver, y, lambda, kappa, gamma, recCliSim, socCliSim, seedsB, &ivBsim);
  });
  threadSerSim.join();
  threadCliSim.join();

  //Check
  for(int j=0; j<lambda; j++) {
    string index = "ot2"+to_string(j);
    cout << "Servers(" << j << "): " << checkTransscripts(socSer->getRecvCat(index), socSer->getSentCat(index), socSerSim->getRecvCat(index), socSerSim->getSentCat(index)) <<  endl;
    cout << "Clients(" << j << "): " << checkTransscripts(socCli->getRecvCat(index), socCli->getSentCat(index), socCliSim->getRecvCat(index), socCliSim->getSentCat(index)) <<  endl << endl;
  }
}

int main() {
  cout << "covert start" << endl;
  int kappa = 16; //they use 16 bytes, 16*8=128 bits
  int lambda = 8;
  int x = 5;
  int y = 2;

  //runCircuitFiles(kappa);
  startProtocol(kappa, lambda, x, y);
  //runEqualTest(kappa);

  cout << "covert end" << endl;
  return 0;
}
