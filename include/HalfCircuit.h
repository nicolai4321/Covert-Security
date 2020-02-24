#ifndef HALFCIRCUIT_H
#define HALFCIRCUIT_H
#include <string>
#include <vector>
#include "cryptlib.h"
#include "Util.h"
using namespace std;

class HalfCircuit {
  public:
    HalfCircuit(int kappa);
    virtual ~HalfCircuit();
    vector<CryptoPP::byte*> addGate(string gateName);
    vector<CryptoPP::byte*> addGate(string gateName, string gateType, string gateL, string gateR);
    void addXOR(string inputGateL, string inputGateR, string outputGate);
    pair<bool, CryptoPP::byte*> evaluate(vector<CryptoPP::byte*> inputs);
    pair<bool, bool> decode(CryptoPP::byte* enc);

  protected:

  private:
    vector<string> gateOrder;
    map<string, vector<string>> gateInfo; //(gateType, gateL, gateR)
    map<string, vector<CryptoPP::byte*>> gates;
    map<string, CryptoPP::byte*> gatesEvaluated;
    vector<CryptoPP::byte*> gatesOutput;
    int kappa;
    CryptoPP::byte* r;
};

#endif // HALFCIRCUIT_H
