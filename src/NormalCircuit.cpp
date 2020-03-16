#include "NormalCircuit.h"
using namespace std;

NormalCircuit::NormalCircuit(int k, CryptoPP::byte* s) {
  kappa = k;
  seed = s;

  //Constant 0
  vector<CryptoPP::byte*> encsZ = addGate(CONST_ZERO, "CONST", "", "");
  gatesEvaluated[CONST_ZERO] = encsZ.at(0);

  //Constant 1
  vector<CryptoPP::byte*> encsO = addGate(CONST_ONE, "CONST", "", "");
  gatesEvaluated[CONST_ONE] = encsO.at(1);
}

NormalCircuit::~NormalCircuit() {}

CircuitInterface* NormalCircuit::createInstance(int k, CryptoPP::byte* s) {
  return new NormalCircuit(k, s);
}

/*
  Adds a new gate and names it with gateName and adds two encodings
  for false and true
*/
vector<CryptoPP::byte*> NormalCircuit::addGate(string gateName) {
  return addGate(gateName, "INPUT", "", "");
}

/*
  Adds a new gate and names it with gateName and adds two encodings
  for false and true
*/
vector<CryptoPP::byte*> NormalCircuit::addGate(string gateName, string gateType, string gateL, string gateR) {
  CryptoPP::byte *encF = Util::randomByte(kappa, seed, iv); iv++;
  CryptoPP::byte *encT = Util::randomByte(kappa, seed, iv); iv++;

  vector<CryptoPP::byte*> encodings;
  encodings.push_back(encF);
  encodings.push_back(encT);
  gates[gateName] = encodings;

  vector<string> info;
  info.push_back(gateType);
  info.push_back(gateL);
  info.push_back(gateR);
  gateInfo[gateName] = info;

  gateOrder.push_back(gateName);
  if(gateType.compare("INPUT") == 0) nrInputGates++;
  return {encF, encT};
}

/*
  Encodes the gate: H(W_l || W_r) xor (W_o || 0^k)
*/
CryptoPP::byte* NormalCircuit::encodeGate(CryptoPP::byte* encL, CryptoPP::byte* encR, CryptoPP::byte* encO) {
  CryptoPP::byte *zero = new CryptoPP::byte[kappa];
  memset(zero, 0x00, kappa);

  CryptoPP::byte *l = Util::h(Util::mergeBytes(encL, encR, kappa), 2*kappa);
  CryptoPP::byte *r = Util::mergeBytes(encO, zero, kappa);
  return Util::byteOp(l, r, "XOR", 2*kappa);
}

/*
  EQ
*/
void NormalCircuit::addEQ(bool b, string outputGate) {
  string constGate = (b) ? CONST_ONE : CONST_ZERO;
  addEQW(constGate, outputGate);
}

/*
  EQW-gate
*/
void NormalCircuit::addEQW(string inputGate, string outputGate) {
  addGate(outputGate, "EQW", inputGate, inputGate);

  CryptoPP::byte *encF = gates[inputGate].at(0);
  CryptoPP::byte *encT = gates[inputGate].at(1);

  CryptoPP::byte *encFO = gates[outputGate].at(0);
  CryptoPP::byte *encTO = gates[outputGate].at(1);

  vector<CryptoPP::byte*> garbledTable;
  garbledTable.push_back(encodeGate(encF, encF, encFO));
  garbledTable.push_back(encodeGate(encT, encT, encTO));
  asrp.Shuffle(garbledTable.begin(), garbledTable.end());
  garbledTables[outputGate] = garbledTable;
}

/*
  INV-gate
*/
void NormalCircuit::addINV(string inputGate, string outputGate) {
  addGate(outputGate, "XOR", inputGate, CONST_ONE);

  CryptoPP::byte *encFL = gates[inputGate].at(0);
  CryptoPP::byte *encTL = gates[inputGate].at(1);

  //TODO: other value?
  CryptoPP::byte *encTR = gates[CONST_ONE].at(1);

  CryptoPP::byte *encFO = gates[outputGate].at(0);
  CryptoPP::byte *encTO = gates[outputGate].at(1);

  vector<CryptoPP::byte*> garbledTable;
  garbledTable.push_back(encodeGate(encFL, encTR, encTO));
  garbledTable.push_back(encodeGate(encTL, encTR, encFO));
  asrp.Shuffle(garbledTable.begin(), garbledTable.end());
  garbledTables[outputGate] = garbledTable;
}

/*
  XOR-gate
*/
void NormalCircuit::addXOR(string inputGateL, string inputGateR, string outputGate) {
  addGate(outputGate, "XOR", inputGateL, inputGateR);

  CryptoPP::byte *encFL = gates[inputGateL].at(0);
  CryptoPP::byte *encTL = gates[inputGateL].at(1);

  CryptoPP::byte *encFR = gates[inputGateR].at(0);
  CryptoPP::byte *encTR = gates[inputGateR].at(1);

  CryptoPP::byte *encFO = gates[outputGate].at(0);
  CryptoPP::byte *encTO = gates[outputGate].at(1);

  vector<CryptoPP::byte*> garbledTable;
  garbledTable.push_back(encodeGate(encFL, encFR, encFO));
  garbledTable.push_back(encodeGate(encFL, encTR, encTO));
  garbledTable.push_back(encodeGate(encTL, encFR, encTO));
  garbledTable.push_back(encodeGate(encTL, encTR, encFO));
  asrp.Shuffle(garbledTable.begin(), garbledTable.end());
  garbledTables[outputGate] = garbledTable;
}

/*
  AND-gate
*/
void NormalCircuit::addAND(string inputGateL, string inputGateR, string outputGate) {
  addGate(outputGate, "AND", inputGateL, inputGateR);

  CryptoPP::byte *encFL = gates[inputGateL].at(0);
  CryptoPP::byte *encTL = gates[inputGateL].at(1);

  CryptoPP::byte *encFR = gates[inputGateR].at(0);
  CryptoPP::byte *encTR = gates[inputGateR].at(1);

  CryptoPP::byte *encFO = gates[outputGate].at(0);
  CryptoPP::byte *encTO = gates[outputGate].at(1);

  vector<CryptoPP::byte*> garbledTable;
  garbledTable.push_back(encodeGate(encFL, encFR, encFO));
  garbledTable.push_back(encodeGate(encFL, encTR, encFO));
  garbledTable.push_back(encodeGate(encTL, encFR, encFO));
  garbledTable.push_back(encodeGate(encTL, encTR, encTO));
  asrp.Shuffle(garbledTable.begin(), garbledTable.end());
  garbledTables[outputGate] = garbledTable;
}

pair<CryptoPP::byte*, CryptoPP::byte*> NormalCircuit::getConstEnc() {
  pair<CryptoPP::byte*, CryptoPP::byte*> output;
  output.first = gatesEvaluated[CONST_ZERO];
  output.second = gatesEvaluated[CONST_ONE];
  return output;
}

GarbledCircuit* NormalCircuit::exportCircuit() {
  GarbledCircuit *F = new GarbledCircuit();
  F->setKappa(kappa);
  F->setOutputGates(outputGates);
  F->setGateOrder(gateOrder);
  F->setGateInfo(gateInfo);
  F->setConstants(getConstEnc());
  F->setDecodings(getDecodings());
  F->setGarbledTables(garbledTables);
  return F;
}

map<string, vector<CryptoPP::byte*>> NormalCircuit::getGarbledTables() {
  return garbledTables;
}

string NormalCircuit::toString() {
  return "Normal circuit";
}

string NormalCircuit::getType() {
  return NormalCircuit::TYPE;
}
