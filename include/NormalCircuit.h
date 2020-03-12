#ifndef GARBLEDCIRCUIT_H
#define GARBLEDCIRCUIT_H
#include <iostream>
#include <map>
#include <string>
#include <vector>
#include "CircuitInterface.h"
#include "cryptlib.h"
#include "GarbledCircuit.h"
#include "Util.h"
using namespace std;

class NormalCircuit: public CircuitInterface {
  public:
    NormalCircuit(int kappa, unsigned int seed);
    virtual ~NormalCircuit();
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
    virtual GarbledCircuit* exportCircuit();

    map<string, vector<CryptoPP::byte*>> getGarbledTables();

  protected:

  private:
    CryptoPP::byte* encodeGate(CryptoPP::byte* encL, CryptoPP::byte* encR, CryptoPP::byte* encO);
    pair<bool, CryptoPP::byte*> decodeGate(CryptoPP::byte* encL, CryptoPP::byte* encR, CryptoPP::byte* enc);
    vector<CryptoPP::byte*> addGate(string gateName, string gateType, string gateL, string gateR);
    void evaluateGate(string gateL, string gateR, string gateName);

    map<string, vector<CryptoPP::byte*>> garbledTables;
};

#endif // GARBLEDCIRCUIT_H
