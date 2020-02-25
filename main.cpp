#include <iostream>
#include <string>
#include "CircuitInterface.h"
#include "GarbledCircuit.h"
#include "HalfCircuit.h"
#include "PartyA.h"
#include "PartyB.h"
#include "Util.h"
using namespace std;

int main() {

  int kappa = 16;

  //Normal circuit
  clock_t start = clock();
  CircuitInterface *F = new GarbledCircuit(kappa);
  PartyA partyA = PartyA(5);
  PartyB partyB = PartyB(3, kappa, F);
  double durationGC = (clock()-start) / (double) CLOCKS_PER_SEC;

  //Half gates
  start = clock();
  CircuitInterface *G = new HalfCircuit(kappa);
  PartyA pA = PartyA(5);
  PartyB pB = PartyB(3, kappa, G);
  double durationHC = (clock()-start) / (double) CLOCKS_PER_SEC;

  cout << "time: " << durationGC << " (normal)" << endl;
  cout << "time: " << durationHC << " (half gates)" << endl;



  return 0;
}
