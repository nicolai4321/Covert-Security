#include "PartyB.h"
using namespace std;

PartyB::PartyB(int y) {
  int kappa = 16;

  //HALF CIRCUIT
  HalfCircuit G = HalfCircuit(kappa);

  vector<CryptoPP::byte*> g0 = G.addGate("input0");
  vector<CryptoPP::byte*> g1 = G.addGate("input1");
  vector<CryptoPP::byte*> g2 = G.addGate("input2");
  vector<CryptoPP::byte*> g3 = G.addGate("input3");
  G.addXOR("input0", "input1", "gate0");
  G.addXOR("input2", "input3", "gate1");
  G.addAND("gate0", "gate1", "gate2");

  vector<CryptoPP::byte*> inputsG;
  inputsG.push_back(g0.at(1));
  inputsG.push_back(g1.at(0));
  inputsG.push_back(g2.at(1));
  inputsG.push_back(g3.at(0));

  pair<bool, CryptoPP::byte*> evaluateOutputG = G.evaluate(inputsG);
  if(evaluateOutputG.first) {
    CryptoPP::byte* Z = evaluateOutputG.second;
    pair<bool, bool> decodeOutput = G.decode(Z);

    if(decodeOutput.first) {
      cout << "half output: " << decodeOutput.second << endl;
    } else {
      cout << "Error! Decode is invalid" << endl;
    }
  } else {
    cout << "Error! Circuit could not evaluate" << endl;
  }

  //NORMAL CIRCUIT
  /*
  GarbledCircuit F = GarbledCircuit(kappa);

  vector<CryptoPP::byte*> i0 = F.addGate("input0");
  vector<CryptoPP::byte*> i1 = F.addGate("input1");
  vector<CryptoPP::byte*> i2 = F.addGate("input2");
  vector<CryptoPP::byte*> i3 = F.addGate("input3");
  F.addXOR("input0", "input1", "gate0");
  F.addXOR("input2", "input3", "gate1");
  F.addAND("gate0", "gate1", "gate2");

  vector<CryptoPP::byte*> inputs;
  inputs.push_back(i0.at(1));
  inputs.push_back(i1.at(0));
  inputs.push_back(i2.at(1));
  inputs.push_back(i3.at(0));

  pair<bool, CryptoPP::byte*> evaluateOutput = F.evaluate(inputs);
  if(evaluateOutput.first) {
    CryptoPP::byte* Z = evaluateOutput.second;
    pair<bool, bool> decodeOutput = F.decode(Z);

    if(decodeOutput.first) {
      cout << "normal output: " << decodeOutput.second << endl;
    } else {
      cout << "Error! Decode is invalid" << endl;
    }
  } else {
    cout << "Error! Circuit could not evaluate" << endl;
  }
  */
}
