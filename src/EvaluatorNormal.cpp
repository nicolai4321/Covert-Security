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
    int kappa = F->getKappa();
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
          CryptoPP::byte *decodedGate = new CryptoPP::byte[2*kappa];
          bool result = decodeGate(encL, encR, b, decodedGate);
          if(result) {
            validEncodings.push_back(decodedGate);
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
bool EvaluatorNormal::decodeGate(CryptoPP::byte *encL, CryptoPP::byte *encR, CryptoPP::byte *enc, CryptoPP::byte *output) {
  int kappa = F->getKappa();

  CryptoPP::byte mergedEncs[2*kappa];
  Util::mergeBytes(encL, encR, kappa, mergedEncs);

  CryptoPP::byte hashMergedEncs[2*kappa];
  h->hashByte(mergedEncs, 2*kappa, hashMergedEncs, 2*kappa);

  CryptoPP::byte decoded[2*kappa];
  Util::xorBytes(hashMergedEncs, enc, decoded, 2*kappa);

  CryptoPP::byte zero[kappa];
  memset(zero, 0x00, kappa);

  if(memcmp((decoded+kappa), zero, kappa) == 0) {
    memcpy(output, decoded, 2*kappa);
    return true;
  } else {
    return false;
  }
}

EvaluatorNormal::EvaluatorNormal(HashInterface *hashInterface) {
  h = hashInterface;
}

EvaluatorNormal::~EvaluatorNormal() {
  vector<string> gateOrder = F->getGateOrder();
  map<string, vector<string>> gateInfo = F->getGateInfo();
  for(string gateName : gateOrder) {
    vector<string> info = gateInfo[gateName];
    string gateType = info.at(0);

    if(gateType.compare("INPUT") != 0 && gateType.compare("CONST") != 0) {
      CryptoPP::byte *b = gatesEvaluated[gateName];
      delete b;
    }
  }
}
