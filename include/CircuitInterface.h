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
    virtual string toString() = 0;
    virtual CircuitInterface* createInstance(int kappa, int seed) = 0;
    virtual pair<CryptoPP::byte*, CryptoPP::byte*> getConstEnc() = 0;

    vector<vector<CryptoPP::byte*>> setOutputGates(vector<string> outputGates);
    pair<bool, vector<bool>> decode(vector<CryptoPP::byte*> encs);
    vector<string> getOutputGates();
    vector<string> getGateOrder();
    map<string, vector<string>> getGateInfo();
    vector<vector<CryptoPP::byte*>> getDecodings();

    inline static const string CONST_ZERO = "constZero";
    inline static const string CONST_ONE = "constOne";

  protected:
    map<string, vector<string>> gateInfo; //(gateType, gateL, gateR)
    map<string, vector<CryptoPP::byte*>> gates;
    map<string, CryptoPP::byte*> gatesEvaluated;
    vector<string> outputGates;
    vector<string> gateOrder;
    CryptoPP::AutoSeededRandomPool asrp;
    int nrInputGates;
    int kappa;
    unsigned int seed;

  private:
};

#endif // CIRCUITINTERFACE_H
