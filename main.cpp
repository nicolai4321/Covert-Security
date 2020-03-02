#include <iostream>
#include <string>
#include "CircuitInterface.h"
#include "CircuitReader.h"
#include "GarbledCircuit.h"
#include "HalfCircuit.h"
#include "PartyA.h"
#include "PartyB.h"
#include "Util.h"
using namespace std;

void runCircuit(CircuitInterface* F, int kappa) {
  clock_t start = clock();
  PartyA partyA = PartyA(5, kappa, F);
  PartyB partyB = PartyB(3);
  double durationGC = (clock()-start) / (double) CLOCKS_PER_SEC;

  cout << "time: " << durationGC << " ("+F->toString()+")" << endl;
}

void runCircuit(CircuitInterface* F, int kappa, string filename, string input) {
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

    double durationGC = (clock()-start) / (double) CLOCKS_PER_SEC;
    cout << "time: " << durationGC << " ("+F->toString()+")" << endl;
  } catch (...) {}
}

int main() {
  string files[8] = {"adder64.txt", "divide64.txt", "udivide.txt", "mult64.txt", "mult2_64.txt", "sub64.txt", "neg64.txt", "zero_equal.txt"};
  int kappa = 16;

  for(string filename : files) {
    cout << "------------------------------" << endl;
    string input = "";
    input += "0101000000000000000000000000000000000000000000000000000000000000";
    if(filename.compare("neg64.txt") != 0 && filename.compare("zero_equal.txt") != 0) {
      input += "0100000000000000000000000000000000000000000000000000000000000000";
    }
    CircuitInterface *F = new GarbledCircuit(kappa);
    CircuitInterface *G = new HalfCircuit(kappa);

    runCircuit(F, kappa, filename, input);
    runCircuit(G, kappa, filename, input);

    cout << "------------------------------" << endl;
  }

  //runCircuit(F, kappa);
  //runCircuit(G, kappa);

  return 0;
}
