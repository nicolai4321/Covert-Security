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
  CircuitInterface *F = new HalfCircuit(kappa);
  //CircuitInterface *F = new GarbledCircuit(kappa);

  PartyA partyA = PartyA(5);
  PartyB partyB = PartyB(3, kappa, F);

  return 0;
}
