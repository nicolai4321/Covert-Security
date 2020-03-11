#ifndef EVALUATORNORMAL_H
#define EVALUATORNORMAL_H
#include <iostream>
#include <string>
#include <vector>
#include "CircuitInterface.h"
#include "cryptlib.h"
#include "GV.h"
using namespace std;

class EvaluatorNormal {
  public:
    EvaluatorNormal(vector<string> outputGates, vector<string> gateOrder, map<string, vector<string>> gateInfo, pair<CryptoPP::byte*,CryptoPP::byte*> constEncs, map<string, vector<CryptoPP::byte*>> garbledTables);
    virtual ~EvaluatorNormal();
    pair<bool, vector<CryptoPP::byte*>> evaluate(vector<CryptoPP::byte*> inputs);
    pair<bool, vector<bool>> decode(vector<vector<CryptoPP::byte*>> decodings, vector<CryptoPP::byte*> encs);

  protected:

  private:
    pair<bool, CryptoPP::byte*> decodeGate(CryptoPP::byte* encL, CryptoPP::byte* encR, CryptoPP::byte* enc);

    map<string, vector<string>> gateInfo;
    vector<string> outputGates;
    vector<string> gateOrder;
    CryptoPP::byte* constZero;
    CryptoPP::byte* constOne;
    map<string, CryptoPP::byte*> gatesEvaluated;
    map<string, vector<CryptoPP::byte*>> garbledTables;
};

#endif // EVALUATORNORMAL_H
