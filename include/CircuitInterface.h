#ifndef CIRCUITINTERFACE_H
#define CIRCUITINTERFACE_H
#include <vector>
#include "cryptlib.h"
using namespace std;

class CircuitInterface {
  public:
    virtual ~CircuitInterface();
    virtual vector<CryptoPP::byte*> addGate(string gateName) = 0;
    virtual void addXOR(string inputGateL, string inputGateR, string outputGate) = 0;
    virtual void addAND(string inputGateL, string inputGateR, string outputGate) = 0;
    virtual pair<bool, CryptoPP::byte*> evaluate(vector<CryptoPP::byte*> inputs) = 0;
    virtual pair<bool, bool> decode(CryptoPP::byte* enc) = 0;

  protected:

  private:
};

#endif // CIRCUITINTERFACE_H
