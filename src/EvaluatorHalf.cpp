#include "EvaluatorHalf.h"
using namespace std;

EvaluatorHalf::EvaluatorHalf(vector<string> oG, vector<string> gOrd, map<string, vector<string>> gI, pair<CryptoPP::byte*,CryptoPP::byte*> cEncs, map<string, vector<CryptoPP::byte*>> andEncs) {
  outputGates = oG;
  gateOrder = gOrd;
  gateInfo = gI;
  constZero = cEncs.first;
  constOne = cEncs.second;
  andEncodings = andEncs;

  gatesEvaluated[CircuitInterface::CONST_ZERO] = constZero;
  gatesEvaluated[CircuitInterface::CONST_ONE] = constOne;
}

EvaluatorHalf::~EvaluatorHalf() {}

/*
  Evaluates the circuit and returns a pair
  the boolean is true if the evaluation was successful
  the vector is the output encodings if the evaluation was succesful
*/
pair<bool, vector<CryptoPP::byte*>> EvaluatorHalf::evaluate(vector<CryptoPP::byte*> inputs) {
  pair<bool, vector<CryptoPP::byte*>> output;
  try {
    int inputIndex = 0;
    for(string gateName : gateOrder) {
      vector<string> info = gateInfo[gateName];
      string gateType = info.at(0);
      string gateL = info.at(1);
      string gateR = info.at(2);

      if(gateType.compare("INPUT") == 0) {
        gatesEvaluated[gateName] = inputs.at(inputIndex);
        inputIndex++;
      } else if(gateType.compare("CONST") == 0) {
      } else if(gateType.compare("XOR") == 0) {
        gatesEvaluated[gateName] = Util::byteOp(gatesEvaluated[gateL], gatesEvaluated[gateR], "XOR", GV::kappa);
      } else if(gateType.compare("AND") == 0) {
        int sa = Util::lsb(gatesEvaluated[gateL], GV::kappa);
        int sb = Util::lsb(gatesEvaluated[gateR], GV::kappa);

        CryptoPP::byte *TG = andEncodings[gateName].at(0);
        CryptoPP::byte *TE = andEncodings[gateName].at(1);
        CryptoPP::byte *Wa = gatesEvaluated[gateL];
        CryptoPP::byte *Wb = gatesEvaluated[gateR];

        CryptoPP::byte *WG = (sa) ?
          Util::byteOp(Util::h(Wa, GV::kappa), TG, "XOR", GV::kappa):
          Util::h(Wa, GV::kappa);

        CryptoPP::byte *WE = (sb) ?
          Util::byteOp(Util::h(Wb, GV::kappa), Util::byteOp(TE, Wa, "XOR", GV::kappa), "XOR", GV::kappa):
          Util::h(Wb, GV::kappa);

        gatesEvaluated[gateName] = Util::byteOp(WG, WE, "XOR", GV::kappa);
      } else {
        cout << "Error! Invalid gate type: " << gateType << endl;
        output.first = false;
        output.second = vector<CryptoPP::byte*>();
        return output;
      }
    }

    //Gets the output
    vector<CryptoPP::byte*> bytes;
    for(string gateName : outputGates) {
      CryptoPP::byte *encodingOutput = gatesEvaluated[gateName];
      bytes.push_back(encodingOutput);
    }

    output.first = true;
    output.second = bytes;
    return output;
  } catch (...) {
    cout << "Error! Could not evaluate circuit" << endl;
    output.first = false;
    output.second = vector<CryptoPP::byte*>();
    return output;
  }
}

/*
  Returns the decoding of the output.
  The bool determines if the decoding was successful
  The vector contains the output value
*/
pair<bool, vector<bool>> EvaluatorHalf::decode(vector<vector<CryptoPP::byte*>> decodings, vector<CryptoPP::byte*> encs) {
  pair<bool, vector<bool>> output;
  vector<bool> outputBools;

  int i=0;
  for(vector<CryptoPP::byte*> v : decodings) {
    CryptoPP::byte *encF = v.at(0);
    CryptoPP::byte *encT = v.at(1);
    CryptoPP::byte *enc = encs.at(i);

    if(memcmp(enc, encF, GV::kappa) == 0) {
      outputBools.push_back(false);
    } else if(memcmp(enc, encT, GV::kappa) == 0) {
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
