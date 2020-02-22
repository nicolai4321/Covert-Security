#include <iostream>
#include "PartyB.h"
#include "GarbledCircuit.h"
#include "cryptlib.h"
using namespace std;

PartyB::PartyB(int y) {
  GarbledCircuit F = GarbledCircuit(16);

  vector<CryptoPP::byte*> i0 = F.addGate("input0");
  vector<CryptoPP::byte*> i1 = F.addGate("input1");
  F.addXOR("input0", "input1", "gate0");

  vector<CryptoPP::byte*> inputs;
  inputs.push_back(i0.at(1));
  inputs.push_back(i1.at(0));

  pair<bool, CryptoPP::byte*> evaluateOutput = F.evaluate(inputs);
  if(evaluateOutput.first) {
    CryptoPP::byte* Z = evaluateOutput.second;

    pair<bool, bool> decodeOutput = F.decode(Z);

    if(decodeOutput.first) {
      cout << decodeOutput.second << endl;
    }
  }
}
