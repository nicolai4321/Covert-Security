#include "CircuitInterface.h"
CircuitInterface::~CircuitInterface() {}

/*
  Sets the output gate
*/
vector<vector<CryptoPP::byte*>> CircuitInterface::setOutputGates(vector<string> oG) {
  outputGates = oG;

  vector<vector<CryptoPP::byte*>> encsOutput;
  for(string s : outputGates) {
    vector<CryptoPP::byte*> encs;
    encs.push_back(gates[s].at(0));
    encs.push_back(gates[s].at(1));
    encsOutput.push_back(encs);
  }

  return encsOutput;
}

/*
  Get the decoding
*/
vector<vector<CryptoPP::byte*>> CircuitInterface::getDecodings() {
  vector<vector<CryptoPP::byte*>> output;
  for(string gateName : outputGates) {
    output.push_back(gates[gateName]);
  }

  return output;
}
