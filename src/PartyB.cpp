#include "PartyB.h"
using namespace std;

PartyB::PartyB(int y, int kappa, CircuitInterface* F) {
  //Input gates
  vector<CryptoPP::byte*> i0 = F->addGate("input0");
  vector<CryptoPP::byte*> i1 = F->addGate("input1");
  vector<CryptoPP::byte*> i2 = F->addGate("input2");
  vector<CryptoPP::byte*> i3 = F->addGate("input3");

  //Gates
  F->addXOR("input0", "input1", "gate0");
  F->addXOR("input2", "input3", "gate1");
  F->addAND("gate0", "gate1", "gate2");

  //Input
  vector<CryptoPP::byte*> inputs;
  inputs.push_back(i0.at(0));
  inputs.push_back(i1.at(1));
  inputs.push_back(i2.at(1));
  inputs.push_back(i3.at(0));

  //Evaluating
  pair<bool, CryptoPP::byte*> evaluateOutput = F->evaluate(inputs);
  if(evaluateOutput.first) {
    CryptoPP::byte* Z = evaluateOutput.second;
    pair<bool, bool> decodeOutput = F->decode(Z);

    if(decodeOutput.first) {
      cout << "Circuit output: " << decodeOutput.second << endl;
    } else {
      cout << "Error! Invalid decoding" << endl;
    }
  } else {
    cout << "Error! Circuit could not evaluate" << endl;
  }
}
