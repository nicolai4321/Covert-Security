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
    void addGate(string gateName);
    void addXOR(string inputGateL, string inputGateR, string outputGate);
    string doubleEncrypt(CryptoPP::byte* m, CryptoPP::byte* keyL, CryptoPP::byte* keyR, CryptoPP::byte* iv);
    CryptoPP::byte* doubleDecrypt(string c, CryptoPP::byte* keyL, CryptoPP::byte* keyR, CryptoPP::byte* iv);

  protected:

  private:
    map<string, vector<CryptoPP::byte*>> gates;
    map<string, vector<string>> garbledTables;
    int kappa;
};

#endif // GARBLEDCIRCUIT_H
