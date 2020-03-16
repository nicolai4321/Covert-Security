#ifndef HALFCIRCUIT_H
#define HALFCIRCUIT_H
#include <iostream>
#include <string>
#include <vector>
#include "CircuitInterface.h"
#include "cryptlib.h"
#include "GarbledCircuit.h"
#include "Util.h"
using namespace std;

class HalfCircuit: public CircuitInterface {
  public:
    HalfCircuit(int kappa, CryptoPP::byte* seed);
    virtual ~HalfCircuit();
    virtual vector<CryptoPP::byte*> addGate(string gateName);
    virtual void addEQ(bool b, string outputGate);
    virtual void addEQW(string inputGate, string outputGate);
    virtual void addINV(string inputGate, string outputGate);
    virtual void addXOR(string inputGateL, string inputGateR, string outputGate);
    virtual void addAND(string inputGateL, string inputGateR, string outputGate);
    virtual string toString();
    virtual CircuitInterface* createInstance(int kappa, CryptoPP::byte* seed);
    virtual pair<CryptoPP::byte*, CryptoPP::byte*> getConstEnc();
    virtual GarbledCircuit* exportCircuit();
    virtual string getType();

    map<string, vector<CryptoPP::byte*>> getAndEncodings();
    inline static const string TYPE = "HALF";

  protected:

  private:
    vector<CryptoPP::byte*> addGate(string gateName, string gateType, string gateL, string gateR, CryptoPP::byte* encF, CryptoPP::byte* encT);

    map<string, vector<CryptoPP::byte*>> andEncodings;
    CryptoPP::byte* r;

};

#endif // HALFCIRCUIT_H
