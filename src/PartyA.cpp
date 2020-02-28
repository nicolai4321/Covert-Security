#include "PartyA.h"
using namespace std;

PartyA::PartyA(int x, int kappa, CircuitInterface* F) {
  //Input gates
  vector<CryptoPP::byte*> i0 = F->addGate("input0");
  vector<CryptoPP::byte*> i1 = F->addGate("input1");
  vector<CryptoPP::byte*> i2 = F->addGate("input2");
  vector<CryptoPP::byte*> i3 = F->addGate("input3");
  vector<CryptoPP::byte*> i4 = F->addGate("input4");
  vector<CryptoPP::byte*> i5 = F->addGate("input5");
  vector<CryptoPP::byte*> i6 = F->addGate("input6");
  vector<CryptoPP::byte*> i7 = F->addGate("input7");

  //Gates
  F->addXOR("input0", "input1", "xorGate0");
  F->addXOR("input2", "input3", "xorGate1");
  F->addXOR("input4", "input5", "xorGate2");
  F->addXOR("input6", "input7", "xorGate3");

  F->addAND("xorGate0", "xorGate1", "andGate0");
  F->addAND("xorGate2", "xorGate3", "andGate1");
  F->addEQW("andGate1", "eqwGate");
  F->addEQ(true, "eqGate");

  //output
  vector<string> outputs;
  outputs.push_back("andGate0");
  outputs.push_back("andGate1");
  outputs.push_back("eqwGate");
  outputs.push_back("eqGate");
  F->setOutputGates(outputs);

  //Input
  vector<CryptoPP::byte*> inputs;
  inputs.push_back(i0.at(1));
  inputs.push_back(i1.at(1));
  inputs.push_back(i2.at(1));
  inputs.push_back(i3.at(0));
  inputs.push_back(i4.at(1));
  inputs.push_back(i5.at(0));
  inputs.push_back(i6.at(1));
  inputs.push_back(i7.at(0));

  //Evaluating
  pair<bool, vector<CryptoPP::byte*>> evaluateOutput = F->evaluate(inputs);

  //Checking valid evaluation
  if(evaluateOutput.first) {
    vector<CryptoPP::byte*> Z = evaluateOutput.second;
    pair<bool, vector<bool>> decodeOutput = F->decode(Z);

    //Checking valid decoding
    if(decodeOutput.first) {
      cout << "Circuit output: ";
      for(bool b : decodeOutput.second) {
        cout << " " << b;
      }
      cout << endl;
    } else {
      cout << "Error! Invalid decoding" << endl;
    }
  } else {
    cout << "Error! Circuit could not evaluate" << endl;
  }
}

PartyA::~PartyA() {}
