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
    virtual void addEQ(bool b, string outputGate) = 0;
    virtual void addEQW(string inputGate, string outputGate) = 0;
    virtual void addINV(string inputGate, string outputGate) = 0;
    virtual void addXOR(string inputGateL, string inputGateR, string outputGate) = 0;
    virtual void addAND(string inputGateL, string inputGateR, string outputGate) = 0;
    virtual pair<bool, vector<CryptoPP::byte*>> evaluate(vector<CryptoPP::byte*> inputs) = 0;

    void setOutputGates(vector<string> outputGates);
    pair<bool, vector<bool>> decode(vector<CryptoPP::byte*> encs);

  protected:
    map<string, vector<string>> gateInfo; //(gateType, gateL, gateR)
    map<string, vector<CryptoPP::byte*>> gates;
    map<string, CryptoPP::byte*> gatesEvaluated;
    vector<string> gatesOutput;
    vector<string> gateOrder;
    bool canEdit = true;
    int nrInputGates;
    int kappa;
    int constCounter = 0;

  private:
};

#endif // CIRCUITINTERFACE_H
