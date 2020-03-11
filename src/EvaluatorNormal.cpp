#include "EvaluatorNormal.h"
using namespace std;

EvaluatorNormal::EvaluatorNormal(vector<string> oG, vector<string> gOrd, map<string, vector<string>> gI, pair<CryptoPP::byte*,CryptoPP::byte*> cEncs, map<string, vector<CryptoPP::byte*>> gT) {
  outputGates = oG;
  gateOrder = gOrd;
  gateInfo = gI;
  constZero = cEncs.first;
  constOne = cEncs.second;
  garbledTables = gT;

  gatesEvaluated[CircuitInterface::CONST_ZERO] = constZero;
  gatesEvaluated[CircuitInterface::CONST_ONE] = constOne;
}

EvaluatorNormal::~EvaluatorNormal() {}

/*
  Evaluates the circuit and returns a pair
  the boolean is true if the evaluation was successful
  the vector is the output encodings if the evaluation was succesful
*/
pair<bool, vector<CryptoPP::byte*>> EvaluatorNormal::evaluate(vector<CryptoPP::byte*> inputs) {
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
      } else {
        vector<CryptoPP::byte*> garbledTable = garbledTables[gateName];
        CryptoPP::byte *encL = gatesEvaluated[gateL];
        CryptoPP::byte *encR = gatesEvaluated[gateR];

        vector<CryptoPP::byte*> validEncodings;
        for(CryptoPP::byte *b : garbledTable) {
          pair<bool, CryptoPP::byte*> result = decodeGate(encL, encR, b);
          if(result.first) {
            validEncodings.push_back(result.second);
          }
        }

        //Check that only one encoding is valid
        if(validEncodings.size() == 1) {
          gatesEvaluated[gateName] = validEncodings.at(0);
        } else if (validEncodings.size() > 1) {
          cout << "Error! Multiple valid encodings" << endl;
          output.first = false;
          output.second = vector<CryptoPP::byte*>();
          return output;
        } else {
          cout << "Error! No valid encodings" << endl;
          output.first = false;
          output.second = vector<CryptoPP::byte*>();
          return output;
        }
      }
    }

    //output gates
    vector<CryptoPP::byte*> bytes;
    for(string gateName : outputGates) {
      CryptoPP::byte *b = gatesEvaluated[gateName];
      bytes.push_back(b);
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
  Decodes a gate if the last characters are zeros
*/
pair<bool, CryptoPP::byte*> EvaluatorNormal::decodeGate(CryptoPP::byte* encL, CryptoPP::byte* encR, CryptoPP::byte* enc) {
  pair<bool, CryptoPP::byte*> output;
  CryptoPP::byte *l = Util::h(Util::mergeBytes(encL, encR, GV::kappa), 2*GV::kappa);
  CryptoPP::byte *decoded = Util::byteOp(l, enc, "XOR", 2*GV::kappa);

  CryptoPP::byte *zero = new CryptoPP::byte[GV::kappa];
  memset(zero, 0x00, GV::kappa);

  CryptoPP::byte *left = new CryptoPP::byte[GV::kappa];
  CryptoPP::byte *right = new CryptoPP::byte[GV::kappa];
  left = decoded;
  right = (decoded+GV::kappa);

  if(memcmp(right, zero, GV::kappa) == 0) {
    output.first = true;
    output.second = left;
    return output;
  } else {
    output.first = false;
    output.second = zero;
    return output;
  }
}

/*
  Returns the decoding of the output.
  The bool determines if the decoding was successful
  The vector contains the output value
*/
pair<bool, vector<bool>> EvaluatorNormal::decode(vector<vector<CryptoPP::byte*>> decodings, vector<CryptoPP::byte*> encs) {
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

