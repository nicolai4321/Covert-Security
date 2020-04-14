#ifndef CIRCUITINTERFACE_H
#define CIRCUITINTERFACE_H
#include <vector>
#include "cryptlib.h"
#include "GarbledCircuit.h"
#include "HashInterface.h"
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
    virtual string toString() = 0;
    virtual CircuitInterface* createInstance(int kappa, CryptoPP::byte* seed) = 0;
    virtual pair<CryptoPP::byte*, CryptoPP::byte*> getConstEnc() = 0;
    virtual void exportCircuit(GarbledCircuit *F) = 0;
    virtual string getType() = 0;

    vector<vector<CryptoPP::byte*>> setOutputGates(vector<string> outputGates);
    vector<vector<CryptoPP::byte*>> getDecodings();

    inline static const string CONST_ZERO = "constZero";
    inline static const string CONST_ONE = "constOne";

  protected:
    map<string, vector<string>> gateInfo; //(gateType, gateL, gateR)
    map<string, vector<CryptoPP::byte*>> gates;
    map<string, CryptoPP::byte*> gatesEvaluated;
    vector<string> outputGates;
    vector<string> gateOrder;
    int nrInputGates;
    int kappa;
    CryptoPP::byte* seed;
    unsigned int iv = 0;

  private:
};

#endif // CIRCUITINTERFACE_H
