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

  CircuitInterface *H = new GarbledCircuit(kappa);
  CircuitReader cr = CircuitReader();
  cr.import(H, "adder64.txt");

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
