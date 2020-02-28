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

int main() {

  int kappa = 16;

  /*
  CircuitInterface *H = new GarbledCircuit(kappa);

  CircuitReader cr = CircuitReader();
  pair<bool, vector<vector<CryptoPP::byte*>>> import = cr.import(H, "neg64.txt");
  if(import.first) {
    vector<vector<CryptoPP::byte*>> encodings = import.second;

    string i0 = "0101000000000000000000000000000000000000000000000000000000000000";
    string i1 = "";//"0100000000000000000000000000000000000000000000000000000000000000";
    string input = i0 + i1;

    vector<CryptoPP::byte*> inputs;
    int i=0;
    for(char c : input) {
      int b = (int) c - 48;
      inputs.push_back(encodings.at(i).at(b));
      i++;
    }
    pair<bool, vector<CryptoPP::byte*>> evaluation = H->evaluate(inputs);

    if(evaluation.first) {
      vector<CryptoPP::byte*> Z = evaluation.second;
      pair<bool, vector<bool>> decoded = H->decode(Z);

      if(decoded.first) {
        vector<bool> z = decoded.second;

        cout << "output: ";
        for(bool b : z) {
          cout << b;
        }
        cout << endl;
      } else {
        cout << "Error! Could not decode" << endl;
      }
    } else {
      cout << "Error! Could not evaluate" << endl;
    }
  } else {
    cout << "Error! Could not import circuit" << endl;
  }
  */

  //Normal circuit
  clock_t start = clock();
  CircuitInterface *F = new GarbledCircuit(kappa);
  PartyA partyA = PartyA(5, kappa, F);
  PartyB partyB = PartyB(3);
  double durationGC = (clock()-start) / (double) CLOCKS_PER_SEC;

  //Half gates
  start = clock();
  CircuitInterface *G = new HalfCircuit(kappa);
  PartyA pA = PartyA(5, kappa, G);
  PartyB pB = PartyB(3);
  double durationHC = (clock()-start) / (double) CLOCKS_PER_SEC;

  cout << "time: " << durationGC << " (normal)" << endl;
  cout << "time: " << durationHC << " (half gates)" << endl;

  return 0;
}
