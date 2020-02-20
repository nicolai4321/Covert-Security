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

  protected:

  private:
    map<string, vector<CryptoPP::byte*>> gates;
    int kappa;
};

#endif // GARBLEDCIRCUIT_H
