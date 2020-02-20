#include "PartyB.h"
#include "GarbledCircuit.h"

PartyB::PartyB(int y) {
  GarbledCircuit F = GarbledCircuit(16);

  F.addGate("input0");
  F.addGate("input1");
  F.addXOR("input0", "input1", "gate0");
}
