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
void runCircuitFiles(int kappa, unsigned int seed) {
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

int main() {
  int kappa = 16;
  unsigned int seed = 3329;
  runCircuitFiles(kappa, seed);

  return 0;
}
