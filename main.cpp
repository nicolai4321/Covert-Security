#include <iostream>
#include <string>
#include "CircuitInterface.h"
#include "CircuitReader.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Network/IOService.h"
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
  unsigned int seed = Util::randomInt(0, 10000);
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

void startProtocol(int kappa, int lambda) {
  //Network
  int port = 1212;
  string ip = "localhost";
  string ipAddress = ip+":"+to_string(port);
  osuCrypto::IOService ios;
  osuCrypto::Channel serverChl = osuCrypto::Session(ios, ipAddress, osuCrypto::SessionMode::Server).addChannel();
  osuCrypto::Channel clientChl = osuCrypto::Session(ios, ipAddress, osuCrypto::SessionMode::Client).addChannel();
  clientChl.waitForConnection();

  //Etc.
  CircuitInterface *circuit = new NormalCircuit(kappa, 0);
  int x = 5;
  int y = 2;

  auto threadA = thread([&]() {
    PartyA partyA = PartyA(x, kappa, lambda, serverChl, clientChl, circuit);
    partyA.startProtocol();
  });
  auto threadB = thread([&]() {
    PartyB partyB = PartyB(y, kappa, lambda, serverChl, clientChl);
    partyB.startProtocol();
  });

  threadA.join();
  threadB.join();
  serverChl.close();
  clientChl.close();
  ios.stop();
}

void otExample() {
  osuCrypto::IOService ios;
  osuCrypto::Channel serverChl = osuCrypto::Session(ios, "localhost:1212", osuCrypto::SessionMode::Server).addChannel();
  osuCrypto::Channel clientChl = osuCrypto::Session(ios, "localhost:1212", osuCrypto::SessionMode::Client).addChannel();
  clientChl.waitForConnection();

  // The number of OTs.
  int n = 2;

  // The code to be run by the OT receiver.
  auto recverThread = thread([&]() {
    osuCrypto::BitVector choices(n);
    choices[0] = 1;
    choices[1] = 0;

    vector<osuCrypto::block> dest(n);
    osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());
    osuCrypto::KosOtExtReceiver recver;
    recver.receiveChosen(choices, dest, prng, clientChl);

    for(int i=0; i<n; i++) {
      cout << i << "," << choices[i] <<":"<< dest[i] << endl;
    }
    cout << endl;

    int data[4] = {0,1,2,3};
    clientChl.asyncSend(move(data));

    clientChl.close();
  });

  auto senderThread = thread([&]() {
    vector<array<osuCrypto::block, 2>> data(n);
    data[0] = {osuCrypto::toBlock(1), osuCrypto::toBlock(2)};
    data[1] = {osuCrypto::toBlock(3), osuCrypto::toBlock(4)};

    for(int i=0; i<n; i++) {
      cout << i << ",0:" << data[i][0] << endl;
      cout << i << ",1:" << data[i][1] << endl;
    }
    cout << endl;

    osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());
    osuCrypto::KosOtExtSender sender;
    sender.sendChosen(data, prng, serverChl);

    int dest[4];
    serverChl.recv(dest);
    for(int i : dest) {
      cout << i << ",";
    }
    cout << endl;

    serverChl.close();
  });

  recverThread.join();
  senderThread.join();
  ios.stop();
}

void tmp(CircuitInterface* c, EvaluatorInterface *e) {
  vector<CryptoPP::byte*> enc0 = c->addGate("i0");
  vector<CryptoPP::byte*> enc1 = c->addGate("i1");
  vector<CryptoPP::byte*> enc2 = c->addGate("i2");
  vector<CryptoPP::byte*> enc3 = c->addGate("i3");
  c->addEQ(true, "n0");
  c->addEQ(false, "n1");

  c->addAND("i0", "i1", "and0");
  c->addAND("i2", "i3", "and1");
  c->addAND("n0", "n1", "and2");
  c->addINV("and0", "inv0");
  c->addEQW("i0", "eqw0");
  c->addXOR("i0", "i1", "xor0");

  vector<string> outputs;
  outputs.push_back("and0");
  outputs.push_back("and1");
  outputs.push_back("and2");
  outputs.push_back("inv0");
  outputs.push_back("eqw0");
  outputs.push_back("xor0");

  c->setOutputGates(outputs);

  vector<CryptoPP::byte*> inputs;
  inputs.push_back(enc0.at(1));
  inputs.push_back(enc1.at(1));
  inputs.push_back(enc2.at(1));
  inputs.push_back(enc3.at(1));

  GarbledCircuit *F = c->exportCircuit();
  e->giveCircuit(F);
  pair<bool, vector<CryptoPP::byte*>> evaluated = e->evaluate(inputs);
  if(evaluated.first) {
    pair<bool, vector<bool>> decoded = e->decode(evaluated.second);
    if(decoded.first) {
        for(bool b : decoded.second) {
          cout << b;
        }
        cout << endl;
    } else {
      cout << "Error! Could not decode" << endl;
    }
  } else {
    cout << "Error! Could not evaluate" << endl;
  }
}

int main() {
  cout << "covert start" << endl;
  int kappa = 16;
  int lambda = 8;

  //otExample();
  runCircuitFiles(kappa);
  //startProtocol(kappa, lambda);

  /*
  CircuitInterface *circuitN = new NormalCircuit(kappa, 2);
  CircuitInterface *circuitH = new HalfCircuit(kappa, 2);

  EvaluatorInterface *evalN = new EvaluatorNormal();
  EvaluatorInterface *evalH = new EvaluatorHalf();
  tmp(circuitN, evalN);
  tmp(circuitH, evalH);
  */

  cout << "covert end" << endl;
  return 0;
}
