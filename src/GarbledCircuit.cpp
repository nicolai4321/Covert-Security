#include "GarbledCircuit.h"
#include "Util.h"
#include <string>
#include <vector>
#include <map>

GarbledCircuit::GarbledCircuit() {
}

std::vector<std::string> GarbledCircuit::addGate(std::string gateName) {
  std::vector<std::string> encodings;
  encodings.push_back(Util::randomString());
  encodings.push_back(Util::randomString());

  //TODO: permute?

  gates[gateName] = encodings;
  return encodings;
}

void GarbledCircuit::addXOR(std::string inputGateL, std::string inputGateR, std::string outputGate) {
  std::string falseEncodingL = gates[inputGateL].at(0);
  std::string trueEncodingL = gates[inputGateL].at(1);
  std::string falseEncodingR = gates[inputGateL].at(0);
  std::string trueEncodingR = gates[inputGateL].at(1);

  Util::printl(falseEncodingL);
  Util::printl(falseEncodingR);
}

