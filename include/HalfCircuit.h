#ifndef HALFCIRCUIT_H
#define HALFCIRCUIT_H
#include <iostream>
#include <string>
#include <vector>
#include "CircuitInterface.h"
#include "cryptlib.h"
#include "Util.h"
using namespace std;

class HalfCircuit: public CircuitInterface {
  public:
    HalfCircuit(int kappa);
    virtual ~HalfCircuit();
    virtual vector<CryptoPP::byte*> addGate(string gateName);
    virtual void addXOR(string inputGateL, string inputGateR, string outputGate);
    virtual void addAND(string inputGateL, string inputGateR, string outputGate);
    virtual pair<bool, CryptoPP::byte*> evaluate(vector<CryptoPP::byte*> inputs);
    virtual pair<bool, bool> decode(CryptoPP::byte* enc);

  protected:

  private:
    vector<CryptoPP::byte*> addGate(string gateName, string gateType, string gateL, string gateR, CryptoPP::byte* encF, CryptoPP::byte* encT);

    map<string, vector<string>> gateInfo; //(gateType, gateL, gateR)
    map<string, vector<CryptoPP::byte*>> gates;
    map<string, vector<CryptoPP::byte*>> andEncodings;
    map<string, CryptoPP::byte*> gatesEvaluated;
    vector<CryptoPP::byte*> gatesOutput;
    vector<string> gateOrder;
    CryptoPP::byte* r;
    int kappa;
};

#endif // HALFCIRCUIT_H
