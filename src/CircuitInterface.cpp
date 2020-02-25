#include "CircuitInterface.h"
CircuitInterface::~CircuitInterface() {}

/*
  Sets the output gate
*/
void CircuitInterface::setOutputGate(string outputGate) {
  if(canEdit) {
    vector<CryptoPP::byte*> encodings = gates[outputGate];
    gatesOutput.push_back(encodings.at(0));
    gatesOutput.push_back(encodings.at(1));
    canEdit = false;
  }
}

/*
  Returns the decoding of the output.
  The first bool determines if the decoding was successful
  The second bool determines the output value
*/
pair<bool, bool> CircuitInterface::decode(CryptoPP::byte* enc) {
  pair<bool, bool> output;
  if(canEdit) {
    Util::printl("Error! Cannot decode before circuit is build");
    output.first = false;
    output.second = false;
  } else {
    if(memcmp(enc, gatesOutput.at(0), kappa) == 0) {
      output.first = true;
      output.second = false;
    } else if(memcmp(enc, gatesOutput.at(1), kappa) == 0) {
      output.first = true;
      output.second = true;
    } else {
      Util::printl("Error! Invalid decoding");
      output.first = false;
      output.second = false;
    }
  }
  return output;
}
