#include "NormalCircuit.h"
using namespace std;

CircuitInterface* NormalCircuit::createInstance(int k, CryptoPP::byte *s) {
  return new NormalCircuit(k, s, h);
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
  CryptoPP::byte *encF = new CryptoPP::byte[kappa];
  CryptoPP::byte *encT = new CryptoPP::byte[kappa];
  iv = Util::randomByte(&prng, encF, kappa, seed, kappa, iv);
  iv = Util::randomByte(&prng, encT, kappa, seed, kappa, iv);

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
CryptoPP::byte* NormalCircuit::encodeGate(CryptoPP::byte *encL, CryptoPP::byte *encR, CryptoPP::byte *encO) {
  CryptoPP::byte zero[kappa];
  memset(zero, 0x00, kappa);

  CryptoPP::byte encLR[2*kappa];
  Util::mergeBytes(encL, encR, kappa, encLR);

  CryptoPP::byte hashEncLR[2*kappa];
  h->hashByte(encLR, 2*kappa, hashEncLR, 2*kappa);

  CryptoPP::byte right[2*kappa];
  Util::mergeBytes(encO, zero, kappa, right);

  CryptoPP::byte *output = new CryptoPP::byte[2*kappa];
  Util::xorBytes(hashEncLR, right, output, 2*kappa);
  return output;
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

  Util::shuffle(&prng, garbledTable, seed, kappa, iv); iv++;
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

  Util::shuffle(&prng, garbledTable, seed, kappa, iv); iv++;
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
  Util::shuffle(&prng, garbledTable, seed, kappa, iv); iv++;
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
  Util::shuffle(&prng, garbledTable, seed, kappa, iv); iv++;
  garbledTables[outputGate] = garbledTable;
}

pair<CryptoPP::byte*, CryptoPP::byte*> NormalCircuit::getConstEnc() {
  pair<CryptoPP::byte*, CryptoPP::byte*> output;
  output.first = gatesEvaluated[CONST_ZERO];
  output.second = gatesEvaluated[CONST_ONE];
  return output;
}

void NormalCircuit::exportCircuit(GarbledCircuit *F) {
  F->setKappa(kappa);
  F->setOutputGates(outputGates);
  F->setGateOrder(gateOrder);
  F->setGateInfo(gateInfo);
  F->setConstants(getConstEnc());
  F->setDecodings(getDecodings());
  F->setGarbledTables(garbledTables);
}

map<string, vector<CryptoPP::byte*>> NormalCircuit::getGarbledTables() {
  return garbledTables;
}

string NormalCircuit::toString() {
  return "Normal circuit (hash: " + h->toString() + ")";
}

string NormalCircuit::getType() {
  return NormalCircuit::TYPE;
}

NormalCircuit::NormalCircuit(int k, CryptoPP::byte* s, HashInterface *hashInterface) {
  kappa = k;
  seed = s;
  h = hashInterface;

  //Constant 0
  vector<CryptoPP::byte*> encsZ = addGate(CONST_ZERO, "CONST", "", "");
  gatesEvaluated[CONST_ZERO] = encsZ.at(0);

  //Constant 1
  vector<CryptoPP::byte*> encsO = addGate(CONST_ONE, "CONST", "", "");
  gatesEvaluated[CONST_ONE] = encsO.at(1);
}

NormalCircuit::~NormalCircuit() {
  for(string gateName : gateOrder) {
    vector<CryptoPP::byte*> encodings = gates[gateName];
    delete encodings.at(0);
    delete encodings.at(1);

    vector<string> info = gateInfo[gateName];
    string gateType = info.at(0);
    if(gateType.compare("AND") == 0 ||
       gateType.compare("XOR") == 0 ||
       gateType.compare("INV") == 0 ||
       gateType.compare("EQW") == 0) {

      vector<CryptoPP::byte*> garbledTable = garbledTables[gateName];
      for(CryptoPP::byte* b : garbledTable) {
        delete b;
      }
    }
  }
}
