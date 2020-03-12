#include "EvaluatorHalf.h"
using namespace std;

EvaluatorHalf::EvaluatorHalf() {}
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
        gatesEvaluated[gateName] = Util::byteOp(gatesEvaluated[gateL], gatesEvaluated[gateR], "XOR", kappa);
      } else if(gateType.compare("AND") == 0) {
        int sa = Util::lsb(gatesEvaluated[gateL], kappa);
        int sb = Util::lsb(gatesEvaluated[gateR], kappa);
        CryptoPP::byte *TG = andEncodings[gateName].at(0);
        CryptoPP::byte *TE = andEncodings[gateName].at(1);
        CryptoPP::byte *Wa = gatesEvaluated[gateL];
        CryptoPP::byte *Wb = gatesEvaluated[gateR];

        CryptoPP::byte *WG = (sa) ?
          Util::byteOp(Util::h(Wa, kappa), TG, "XOR", kappa):
          Util::h(Wa, kappa);

        CryptoPP::byte *WE = (sb) ?
          Util::byteOp(Util::h(Wb, kappa), Util::byteOp(TE, Wa, "XOR", kappa), "XOR", kappa):
          Util::h(Wb, kappa);

        gatesEvaluated[gateName] = Util::byteOp(WG, WE, "XOR", kappa);
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
