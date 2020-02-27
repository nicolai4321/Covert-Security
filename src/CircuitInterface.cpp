#include "CircuitInterface.h"
CircuitInterface::~CircuitInterface() {}

/*
  Sets the output gate
*/
void CircuitInterface::setOutputGates(vector<string> outputGates) {
  if(canEdit) {
    gatesOutput = outputGates;
    canEdit = false;
  }
}

/*
  Returns the decoding of the output.
  The bool determines if the decoding was successful
  The vector contains the output value
*/
pair<bool, vector<bool>> CircuitInterface::decode(vector<CryptoPP::byte*> encs) {
  pair<bool, vector<bool>> output;
  vector<bool> outputBools;
  if(canEdit) {
    Util::printl("Error! Cannot decode before circuit is build");
    output.first = false;
    output.second = outputBools;
    return output;
  } else {
    int i=0;
    for(string gateName : gatesOutput) {
      CryptoPP::byte *encF = gates[gateName].at(0);
      CryptoPP::byte *encT = gates[gateName].at(1);
      CryptoPP::byte *enc = encs.at(i);

      if(memcmp(enc, encF, kappa) == 0) {
        outputBools.push_back(false);
      } else if(memcmp(enc, encT, kappa) == 0) {
        outputBools.push_back(true);
      } else {
        Util::printl("Error! Invalid decoding");
        output.first = false;
        output.second = outputBools;
        return output;
      }
      i++;
    }
  }

  output.first = true;
  output.second = outputBools;
  return output;
}
