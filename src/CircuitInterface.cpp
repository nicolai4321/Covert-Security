#include "CircuitInterface.h"
CircuitInterface::~CircuitInterface() {}

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

