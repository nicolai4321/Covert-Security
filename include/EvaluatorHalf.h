#ifndef EVALUATORHALF_H
#define EVALUATORHALF_H
#include <iostream>
#include <map>
#include <string>
#include <vector>
#include "CircuitInterface.h"
#include "cryptlib.h"
#include "GV.h"
#include "Util.h"
using namespace std;

class EvaluatorHalf
{
  public:
    EvaluatorHalf(vector<string> outputGates, vector<string> gateOrder, map<string, vector<string>> gateInfo, pair<CryptoPP::byte*,CryptoPP::byte*> constEncodings, map<string, vector<CryptoPP::byte*>> andEncodings);
    virtual ~EvaluatorHalf();
    pair<bool, vector<CryptoPP::byte*>> evaluate(vector<CryptoPP::byte*> inputs);
    pair<bool, vector<bool>> decode(vector<vector<CryptoPP::byte*>> decodings, vector<CryptoPP::byte*> encs);

  protected:

  private:
    vector<string> outputGates;
    vector<string> gateOrder;
    map<string, vector<string>> gateInfo;
    map<string, CryptoPP::byte*> gatesEvaluated;
    CryptoPP::byte* constZero;
    CryptoPP::byte* constOne;
    map<string, vector<CryptoPP::byte*>> andEncodings;
};

#endif // EVALUATORHALF_H
