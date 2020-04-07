#include "EvaluatorNormal.h"
using namespace std;

/*
  Evaluates the circuit and returns a pair
  the boolean is true if the evaluation was successful
  the vector is the output encodings if the evaluation was succesful
*/
pair<bool, vector<CryptoPP::byte*>> EvaluatorNormal::evaluate(vector<CryptoPP::byte*> inputs) {
  pair<bool, vector<CryptoPP::byte*>> output;
  try {
    int inputIndex = 0;
    vector<string> gateOrder = F->getGateOrder();
    map<string, vector<string>> gateInfo = F->getGateInfo();
    map<string, vector<CryptoPP::byte*>> garbledTables = F->getGarbledTables();
    for(string gateName : gateOrder) {
      vector<string> info = gateInfo[gateName];
      string gateType = info.at(0);
      string gateL = info.at(1);
      string gateR = info.at(2);

      if(gateType.compare("INPUT") == 0) {
        gatesEvaluated[gateName] = inputs.at(inputIndex);
        inputIndex++;
      } else if(gateType.compare("CONST") != 0) {
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
    vector<string> outputGates = F->getOutputGates();
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
  int kappa = F->getKappa();

  CryptoPP::byte *l = h->hashByte(Util::mergeBytes(encL, encR, kappa), 2*kappa);
  CryptoPP::byte *decoded = Util::byteOp(l, enc, "XOR", 2*kappa);

  CryptoPP::byte *zero = new CryptoPP::byte[kappa];
  memset(zero, 0x00, kappa);

  CryptoPP::byte *left = new CryptoPP::byte[kappa];
  CryptoPP::byte *right = new CryptoPP::byte[kappa];
  left = decoded;
  right = (decoded+kappa);

  if(memcmp(right, zero, kappa) == 0) {
    output.first = true;
    output.second = left;
    return output;
  } else {
    output.first = false;
    output.second = zero;
    return output;
  }
}

EvaluatorNormal::EvaluatorNormal(HashInterface *hashInterface) {
  h = hashInterface;
}

EvaluatorNormal::~EvaluatorNormal() {}
