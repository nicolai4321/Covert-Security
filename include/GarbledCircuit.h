#ifndef GARBLEDCIRCUIT_H
#define GARBLEDCIRCUIT_H
#include <string>
#include <vector>
#include <map>

using namespace std;

class GarbledCircuit
{
  public:
    GarbledCircuit();
    vector<string> addGate(string gateName);
    void addXOR(string inputGateL, string inputGateR, string outputGate);

  protected:

  private:
    map<string, vector<string>> gates;
};

#endif // GARBLEDCIRCUIT_H
