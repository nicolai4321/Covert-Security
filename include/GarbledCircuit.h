#ifndef GARBLEDCIRCUIT_H
#define GARBLEDCIRCUIT_H
#include <iostream>
#include <map>
#include <string>
#include <vector>
#include "CircuitInterface.h"
#include "cryptlib.h"
#include "Util.h"
using namespace std;

class GarbledCircuit: public CircuitInterface {
  public:
    GarbledCircuit(int k);
    virtual ~GarbledCircuit();
    virtual vector<CryptoPP::byte*> addGate(string gateName);
    virtual void addINV(string inputGate, string outputGate);
    virtual void addXOR(string inputGateL, string inputGateR, string outputGate);
    virtual void addAND(string inputGateL, string inputGateR, string outputGate);
    virtual pair<bool, vector<CryptoPP::byte*>> evaluate(vector<CryptoPP::byte*> inputs);

  protected:

  private:
    vector<CryptoPP::byte*> addGate(string gateName, string gateType, string gateL, string gateR);
    void evaluateGate(string gateL, string gateR, string gateName);
    string doubleEncrypt(CryptoPP::byte* m, CryptoPP::byte* keyL, CryptoPP::byte* keyR, CryptoPP::byte* iv);
    CryptoPP::byte* doubleDecrypt(string c, CryptoPP::byte* keyL, CryptoPP::byte* keyR, CryptoPP::byte* iv);

    map<string, vector<string>> garbledTables;
    CryptoPP::byte *iv;
};

#endif // GARBLEDCIRCUIT_H
