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
    HalfCircuit(int kappa, unsigned int seed);
    virtual ~HalfCircuit();
    virtual vector<CryptoPP::byte*> addGate(string gateName);
    virtual void addEQ(bool b, string outputGate);
    virtual void addEQW(string inputGate, string outputGate);
    virtual void addINV(string inputGate, string outputGate);
    virtual void addXOR(string inputGateL, string inputGateR, string outputGate);
    virtual void addAND(string inputGateL, string inputGateR, string outputGate);
    virtual pair<bool, vector<CryptoPP::byte*>> evaluate(vector<CryptoPP::byte*> inputs);
    virtual string toString();
    virtual CircuitInterface* createInstance(int kappa, int seed);
    virtual pair<CryptoPP::byte*, CryptoPP::byte*> getConstEnc();
    map<string, vector<CryptoPP::byte*>> getAndEncodings();

  protected:

  private:
    vector<CryptoPP::byte*> addGate(string gateName, string gateType, string gateL, string gateR, CryptoPP::byte* encF, CryptoPP::byte* encT);

    map<string, vector<CryptoPP::byte*>> andEncodings;
    CryptoPP::byte* r;

};

#endif // HALFCIRCUIT_H
