#include "GarbledCircuit.h"
using namespace std;

GarbledCircuit::GarbledCircuit(){}
GarbledCircuit::~GarbledCircuit(){}

void GarbledCircuit::setKappa(int k) {
  kappa = k;
}

void GarbledCircuit::setOutputGates(vector<string> oG) {
  outputGates = oG;
}

void GarbledCircuit::setGateOrder(vector<string> gO) {
  gateOrder = gO;
}

void GarbledCircuit::setGateInfo(map<string, vector<string>> gI) {
  gateInfo = gI;
}

void GarbledCircuit::setConstants(pair<CryptoPP::byte*, CryptoPP::byte*> cE) {
  constEncs = cE;
}

void GarbledCircuit::setAndEncodings(map<string, vector<CryptoPP::byte*>> aE) {
  andEncodings = aE;
}

void GarbledCircuit::setGarbledTables(map<string, vector<CryptoPP::byte*>> gT) {
  garbledTables = gT;
}

void GarbledCircuit::setDecodings(vector<vector<CryptoPP::byte*>> d) {
  decodings = d;
}

int GarbledCircuit::getKappa() {
  return kappa;
}

vector<string> GarbledCircuit::getOutputGates() {
  return outputGates;
}

vector<string> GarbledCircuit::getGateOrder() {
  return gateOrder;
}

map<string, vector<string>> GarbledCircuit::getGateInfo() {
  return gateInfo;
}

pair<CryptoPP::byte*, CryptoPP::byte*> GarbledCircuit::getConstants() {
  return constEncs;
}

map<string, vector<CryptoPP::byte*>> GarbledCircuit::getAndEncodings() {
  return andEncodings;
}

map<string, vector<CryptoPP::byte*>> GarbledCircuit::getGarbledTables() {
  return garbledTables;
}

vector<vector<CryptoPP::byte*>> GarbledCircuit::getDecodings() {
  return decodings;
}
