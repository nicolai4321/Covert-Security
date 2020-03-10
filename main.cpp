#include <iostream>
#include <string>
#include "CircuitInterface.h"
#include "CircuitReader.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Network/IOService.h"
#include "GarbledCircuit.h"
#include "HalfCircuit.h"
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
double runCircuit(CircuitInterface* F, int kappa, string filename, string input) {
  try {
    CircuitReader cr = CircuitReader();
    pair<bool, vector<vector<CryptoPP::byte*>>> import = cr.import(F, filename);

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
      if(i == cr.getInputGates()) {
        string msg = "Error! To many input gates";
        cout << msg << endl;
        throw msg;
      }
      int b = (int) c - 48;
      inputs.push_back(encodings.at(i).at(b));
      i++;
    }

    if(i != cr.getInputGates()) {
        string msg = "Error! To few input gates";
        cout << msg << endl;
        throw msg;
    }

    pair<bool, vector<CryptoPP::byte*>> evaluation = F->evaluate(inputs);
    if(!evaluation.first) {
      string msg = "Error! Could not evaluate circuit";
      cout << msg << endl;
      throw msg;
    }

    vector<CryptoPP::byte*> Z = evaluation.second;
    pair<bool, vector<bool>> decoded = F->decode(Z);

    if(!decoded.first) {
      string msg = "Error! Could not decode the encoding";
      cout << msg << endl;
      throw msg;
    }

    vector<bool> z = decoded.second;

    cout << "output: ";
    for(bool b : z) {
      cout << b;
    }
    cout << endl;

    double duration = (clock()-start) / (double) CLOCKS_PER_SEC;
    return duration;
  } catch (...) {
    return 0;
  }
}

/*
  Runs the circuit files
*/
void runCircuitFiles(int kappa) {
  unsigned int seed = 3329;
  string files[8] = {"adder64.txt", "divide64.txt", "udivide.txt", "mult64.txt", "mult2_64.txt", "sub64.txt", "neg64.txt", "zero_equal.txt"};

  double timeTotal0 = 0;
  double timeTotal1 = 0;

  for(string filename : files) {
    cout << filename << endl;
    string input = "";
    input += "0101000000000000000000000000000000000000000000000000000000000000"; //10
    if(filename.compare("neg64.txt") != 0 && filename.compare("zero_equal.txt") != 0) {
      input += "0100000000000000000000000000000000000000000000000000000000000000"; //2
    }
    CircuitInterface *F = new GarbledCircuit(kappa, seed);
    CircuitInterface *G = new HalfCircuit(kappa, seed);

    double time0 = runCircuit(F, kappa, filename, input);
    double time1 = runCircuit(G, kappa, filename, input);
    timeTotal0 += time0;
    timeTotal1 += time1;

    cout << "Time: " << time0 << " ("+F->toString()+"), " << time1 << " ("+G->toString()+")" << endl;
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
  CircuitInterface *F = new GarbledCircuit(kappa, 0);
  int x = 5;
  int y = 2;

  auto threadA = thread([&]() {
    PartyA partyA = PartyA(x, kappa, lambda, serverChl, clientChl, F);
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

int main() {
  cout << "covert start" << endl;
  int kappa = 16;
  int lambda = 8;

  //otExample();
  //runCircuitFiles(kappa);
  startProtocol(kappa, lambda);

  cout << "covert end" << endl;
  return 0;
}
