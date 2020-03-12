#include "EvaluatorInterface.h"
using namespace std;

EvaluatorInterface::EvaluatorInterface() {}
EvaluatorInterface::~EvaluatorInterface() {}

void EvaluatorInterface::giveCircuit(GarbledCircuit* gC) {
  F = gC;
  gatesEvaluated[CircuitInterface::CONST_ZERO] = F->getConstants().first;
  gatesEvaluated[CircuitInterface::CONST_ONE] = F->getConstants().second;
}

/*
  Returns the decoding of the output.
  The bool determines if the decoding was successful
  The vector contains the output value
*/
pair<bool, vector<bool>> EvaluatorInterface::decode(vector<CryptoPP::byte*> encs) {
  pair<bool, vector<bool>> output;
  vector<bool> outputBools;
  int kappa = F->getKappa();

  int i=0;
  vector<vector<CryptoPP::byte*>> decodings = F->getDecodings();
  for(vector<CryptoPP::byte*> v : decodings) {
    CryptoPP::byte *encF = v.at(0);
    CryptoPP::byte *encT = v.at(1);
    CryptoPP::byte *enc = encs.at(i);

    if(memcmp(enc, encF, kappa) == 0) {
      outputBools.push_back(false);
    } else if(memcmp(enc, encT, kappa) == 0) {
      outputBools.push_back(true);
    } else {
      Util::printl("Error! Invalid decoding");
      output.first = false;
      output.second = vector<bool>();
      return output;
    }
    i++;
  }

  output.first = true;
  output.second = outputBools;
  return output;
}
