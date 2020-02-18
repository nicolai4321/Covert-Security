#include "GarbledCircuit.h"
#include "Util.h"
#include <string>
#include <vector>
#include <map>

GarbledCircuit::GarbledCircuit() {}

std::vector<std::string> GarbledCircuit::addGate(std::string gateName) {
  std::vector<std::string> encodings;

  string s0 = Util::randomString(32);
  string s1 = Util::randomString(32);

  encodings.push_back(s0);
  encodings.push_back(s1);

  //TODO: permute?

  gates[gateName] = encodings;
  return encodings;
}

void GarbledCircuit::addXOR(std::string inputGateL, std::string inputGateR, std::string outputGate) {
  std::string falseEncodingL = gates[inputGateL].at(0);
  std::string trueEncodingL = gates[inputGateL].at(1);
  std::string falseEncodingR = gates[inputGateR].at(0);
  std::string trueEncodingR = gates[inputGateR].at(1);

  Util::printl(falseEncodingL);
  Util::printl(trueEncodingL);
  Util::printl(falseEncodingR);
  Util::printl(trueEncodingR);

}
