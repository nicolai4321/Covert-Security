#ifndef GARBLEDCIRCUIT_H
#define GARBLEDCIRCUIT_H
#include <string>
#include <vector>
#include <map>

class GarbledCircuit
{
  public:
    std::map<std::string, std::vector<std::string>> gates;

    GarbledCircuit();
    std::vector<std::string> addGate(std::string gateName);
    void addXOR(std::string inputGateL, std::string inputGateR, std::string outputGate);

  protected:

  private:
};

#endif // GARBLEDCIRCUIT_H
