#include "EvaluatorHalf.h"
using namespace std;

/*
  Evaluates the circuit and returns a pair
  the boolean is true if the evaluation was successful
  the vector is the output encodings if the evaluation was succesful
*/
pair<bool, vector<CryptoPP::byte*>> EvaluatorHalf::evaluate(vector<CryptoPP::byte*> inputs) {
  pair<bool, vector<CryptoPP::byte*>> output;
  try {
    int inputIndex = 0;
    int kappa = F->getKappa();
    vector<string> gateOrder = F->getGateOrder();
    map<string, vector<string>> gateInfo = F->getGateInfo();
    map<string, vector<CryptoPP::byte*>> andEncodings = F->getAndEncodings();
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
        CryptoPP::byte *xorLR = new CryptoPP::byte[kappa];
        Util::xorBytes(gatesEvaluated[gateL], gatesEvaluated[gateR], xorLR, kappa);
        gatesEvaluated[gateName] = xorLR;
      } else if(gateType.compare("AND") == 0) {
        int sa = Util::lsb(gatesEvaluated[gateL], kappa);
        int sb = Util::lsb(gatesEvaluated[gateR], kappa);
        CryptoPP::byte *TG = andEncodings[gateName].at(0);
        CryptoPP::byte *TE = andEncodings[gateName].at(1);
        CryptoPP::byte *Wa = gatesEvaluated[gateL];
        CryptoPP::byte *Wb = gatesEvaluated[gateR];

        //WG
        CryptoPP::byte hashWa[kappa];
        h->hashByte(Wa, kappa, hashWa, kappa);

        CryptoPP::byte xorHashWaTG[kappa];
        Util::xorBytes(hashWa, TG, xorHashWaTG, kappa);

        CryptoPP::byte *WG = (sa) ? xorHashWaTG : hashWa;

        //WE
        CryptoPP::byte hashWb[kappa];
        h->hashByte(Wb, kappa, hashWb, kappa);

        CryptoPP::byte xorTEWe[kappa];
        Util::xorBytes(TE, Wa, xorTEWe, kappa);

        CryptoPP::byte xorHashWbTeWE[kappa];
        Util::xorBytes(hashWb, xorTEWe, xorHashWbTeWE, kappa);

        CryptoPP::byte *WE = (sb) ? xorHashWbTeWE : hashWb;

        //evaluated
        CryptoPP::byte *xorWGWE = new CryptoPP::byte[kappa];
        Util::xorBytes(WG, WE, xorWGWE, kappa);

        gatesEvaluated[gateName] = xorWGWE;
      } else {
        cout << "Error! Invalid gate type: " << gateType << endl;
        output.first = false;
        output.second = vector<CryptoPP::byte*>();
        return output;
      }
    }

    //Gets the output
    vector<CryptoPP::byte*> bytes;
    vector<string> outputGates = F->getOutputGates();
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

EvaluatorHalf::EvaluatorHalf(HashInterface *hashInterface) {
  h = hashInterface;
}

EvaluatorHalf::~EvaluatorHalf() {
  vector<string> gateOrder = F->getGateOrder();
  map<string, vector<string>> gateInfo = F->getGateInfo();
  for(string gateName : gateOrder) {
    vector<string> info = gateInfo[gateName];
    string gateType = info.at(0);
    if(gateType.compare("XOR") == 0 || gateType.compare("AND") == 0) {
      CryptoPP::byte *b = gatesEvaluated[gateName];
      delete b;
    }
  }
}
