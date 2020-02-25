#ifndef CIRCUITINTERFACE_H
#define CIRCUITINTERFACE_H
#include <vector>
#include "cryptlib.h"
#include "Util.h"
using namespace std;

class CircuitInterface {
  public:
    virtual ~CircuitInterface();
    virtual vector<CryptoPP::byte*> addGate(string gateName) = 0;
    virtual void addXOR(string inputGateL, string inputGateR, string outputGate) = 0;
    virtual void addAND(string inputGateL, string inputGateR, string outputGate) = 0;
    virtual pair<bool, CryptoPP::byte*> evaluate(vector<CryptoPP::byte*> inputs) = 0;

    void setOutputGate(string outputGate);
    pair<bool, bool> decode(CryptoPP::byte* enc);

  protected:
    map<string, vector<string>> gateInfo; //(gateType, gateL, gateR)
    map<string, vector<CryptoPP::byte*>> gates;
    map<string, CryptoPP::byte*> gatesEvaluated;
    vector<CryptoPP::byte*> gatesOutput;
    vector<string> gateOrder;
    bool canEdit = true;
    int kappa;

  private:
};

#endif // CIRCUITINTERFACE_H
