#ifndef GARBLEDCIRCUIT_H
#define GARBLEDCIRCUIT_H
#include <string>
#include <vector>
#include <map>
#include "cryptlib.h"

using namespace std;

class GarbledCircuit
{
  public:
    GarbledCircuit(int k);
    vector<CryptoPP::byte*> addGate(string gateName);
    vector<CryptoPP::byte*> addGate(string gateName, string gateType, string gateL, string gateR);
    void addXOR(string inputGateL, string inputGateR, string outputGate);
    pair<bool, CryptoPP::byte*> evaluate(vector<CryptoPP::byte*> inputs);
    string doubleEncrypt(CryptoPP::byte* m, CryptoPP::byte* keyL, CryptoPP::byte* keyR, CryptoPP::byte* iv);
    CryptoPP::byte* doubleDecrypt(string c, CryptoPP::byte* keyL, CryptoPP::byte* keyR, CryptoPP::byte* iv);
    void evaluateInput(vector<CryptoPP::byte*> inputs, int i, string gateName);
    void evaluateXOR(string gateL, string gateR, string gateName);
    pair<bool, bool> decode(CryptoPP::byte* enc);

  protected:

  private:
    vector<string> gateOrder;
    map<string, vector<string>> gateInfo; //(gateType, gateL, gateR)
    map<string, CryptoPP::byte*> gatesEvaluated;
    map<string, vector<CryptoPP::byte*>> gates;
    map<string, vector<string>> garbledTables;
    vector<CryptoPP::byte*> gatesOutput;
    int kappa;
    CryptoPP::byte *iv;
};

#endif // GARBLEDCIRCUIT_H
