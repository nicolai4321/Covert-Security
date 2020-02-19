#ifndef GARBLEDCIRCUIT_H
#define GARBLEDCIRCUIT_H
#include <string>
#include <vector>
#include <map>

using namespace std;

class GarbledCircuit
{
  public:
    GarbledCircuit(int k);
    vector<string> addGate(string gateName);
    void addXOR(string inputGateL, string inputGateR, string outputGate);

  protected:

  private:
    map<string, vector<string>> gates;
    int kappa;
};

#endif // GARBLEDCIRCUIT_H
