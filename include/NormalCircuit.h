#ifndef GARBLEDCIRCUIT_H
#define GARBLEDCIRCUIT_H
#include <iostream>
#include <map>
#include <string>
#include <vector>
#include "CircuitInterface.h"
#include "cryptlib.h"
#include "GarbledCircuit.h"
#include "HashInterface.h"
#include "Util.h"
using namespace std;

class NormalCircuit: public CircuitInterface {
  public:
    NormalCircuit(int kappa, CryptoPP::byte* seed, HashInterface *hashInterface);
    virtual ~NormalCircuit();
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

    map<string, vector<CryptoPP::byte*>> getGarbledTables();
    inline static const string TYPE = "NORMAL";

  protected:

  private:
    map<string, vector<CryptoPP::byte*>> garbledTables;
    HashInterface *h;

    CryptoPP::byte* encodeGate(CryptoPP::byte* encL, CryptoPP::byte* encR, CryptoPP::byte* encO);
    vector<CryptoPP::byte*> addGate(string gateName, string gateType, string gateL, string gateR);
};

#endif // GARBLEDCIRCUIT_H
