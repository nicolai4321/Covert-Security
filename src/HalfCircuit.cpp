#include "HalfCircuit.h"
using namespace std;

HalfCircuit::HalfCircuit(int k, CryptoPP::byte* s) {
  kappa = k;
  seed = s;
  r = Util::randomByte(kappa, seed, iv); iv++;

  //Ensuring that the last bit in r is 1
  unsigned char b = (unsigned char) 1;
  r[kappa-1] = r[kappa-1] | b;

  //Constant 0
  CryptoPP::byte *encFZ = Util::randomByte(kappa, seed, iv); iv++;
  CryptoPP::byte *encTZ = Util::byteOp(encFZ, r, "XOR", kappa);
  vector<CryptoPP::byte*> encsZ = addGate(CONST_ZERO, "CONST", "", "", encFZ, encTZ);
  gatesEvaluated[CONST_ZERO] = encsZ.at(0);

  //Constant 1
  CryptoPP::byte *encFO = Util::randomByte(kappa, seed, iv); iv++;
  CryptoPP::byte *encTO = Util::byteOp(encFO, r, "XOR", kappa);
  vector<CryptoPP::byte*> encsO = addGate(CONST_ONE, "CONST", "", "", encFO, encTO);
  gatesEvaluated[CONST_ONE] = encsO.at(1);
}

HalfCircuit::~HalfCircuit() {}

CircuitInterface* HalfCircuit::createInstance(int k, CryptoPP::byte* s) {
  return new HalfCircuit(k, s);
}

/*
  Adds a new gate and names it with gateName and adds two encodings
  for false and true
*/
vector<CryptoPP::byte*> HalfCircuit::addGate(string gateName) {
  CryptoPP::byte *encF = Util::randomByte(kappa, seed, iv); iv++;
  CryptoPP::byte *encT = Util::byteOp(encF, r, "XOR", kappa);
  return addGate(gateName, "INPUT", "", "", encF, encT);
}

/*
  Adds a new gate and names it with gateName and adds two encodings
  for false and true
*/
vector<CryptoPP::byte*> HalfCircuit::addGate(string gateName, string gateType, string gateL, string gateR, CryptoPP::byte *encF, CryptoPP::byte *encT) {
  vector<CryptoPP::byte*> encodings;
  encodings.push_back(encF);
  encodings.push_back(encT);
  gates[gateName] = encodings;

  vector<string> info;
  info.push_back(gateType);
  info.push_back(gateL);
  info.push_back(gateR);
  gateInfo[gateName] = info;

  if(gateType.compare("INPUT") == 0) nrInputGates++;
  gateOrder.push_back(gateName);
  return encodings;
}

/*
  EQ-gate
*/
void HalfCircuit::addEQ(bool b, string outputGate) {
  string constName = (b) ? CONST_ONE : CONST_ZERO;
  addEQW(constName, outputGate);
}

/*
  EQW-gate
*/
void HalfCircuit::addEQW(string inputGate, string outputGate) {
  CryptoPP::byte *encF = Util::byteOp(gates[inputGate].at(0), gates[CONST_ZERO].at(0), "XOR", kappa);
  CryptoPP::byte *encT = Util::byteOp(encF, r, "XOR", kappa);
  addGate(outputGate, "XOR", inputGate, CONST_ZERO, encF, encT);
}

/*
  INV-gate
*/
void HalfCircuit::addINV(string inputGate, string outputGate) {
  CryptoPP::byte *encF = Util::byteOp(gates[inputGate].at(0), gates[CONST_ONE].at(0), "XOR", kappa);
  CryptoPP::byte *encT = Util::byteOp(encF, r, "XOR", kappa);
  addGate(outputGate, "XOR", inputGate, CONST_ONE, encF, encT);
}

/*
  XOR-gate
*/
void HalfCircuit::addXOR(string inputGateL, string inputGateR, string outputGate) {
  CryptoPP::byte *encF = Util::byteOp(gates[inputGateL].at(0), gates[inputGateR].at(0), "XOR", kappa);
  CryptoPP::byte *encT = Util::byteOp(encF, r, "XOR", kappa);
  addGate(outputGate, "XOR", inputGateL, inputGateR, encF, encT);
}

/*
  AND-gate
*/
void HalfCircuit::addAND(string inputGateL, string inputGateR, string outputGate) {
  vector<CryptoPP::byte*> leftEnc = gates[inputGateL];
  vector<CryptoPP::byte*> rightEnc = gates[inputGateR];
  int pa = Util::lsb(leftEnc.at(0), kappa);
  int pb = Util::lsb(rightEnc.at(0), kappa);

  //Generator part
  CryptoPP::byte *waf = leftEnc.at(0);
  CryptoPP::byte *wat = leftEnc.at(1);

  CryptoPP::byte *WGF = (pa*pb) ?
    Util::byteOp(Util::h(leftEnc.at(pa), kappa), r, "XOR", kappa):
    Util::h(leftEnc.at(pa), kappa);

  CryptoPP::byte *WGT = Util::byteOp(WGF, r, "XOR", kappa);

  CryptoPP::byte *TG = (pb) ?
    Util::byteOp(Util::byteOp(Util::h(waf, kappa), Util::h(wat, kappa), "XOR", kappa), r, "XOR", kappa):
    Util::byteOp(Util::h(waf, kappa), Util::h(wat, kappa), "XOR", kappa);

  //Evaluator part
  CryptoPP::byte *wbf = rightEnc.at(0);
  CryptoPP::byte *wbt = rightEnc.at(1);

  CryptoPP::byte *WEF = Util::h(rightEnc.at(pb), kappa);
  CryptoPP::byte *WET = Util::byteOp(WEF, r, "XOR", kappa);
  CryptoPP::byte *TE = Util::byteOp(Util::byteOp(Util::h(wbf, kappa), Util::h(wbt, kappa), "XOR", kappa), waf, "XOR", kappa);

  //Adding gates
  vector<CryptoPP::byte*> encodings;
  encodings.push_back(TG);
  encodings.push_back(TE);
  andEncodings[outputGate] = encodings;

  CryptoPP::byte *encF = Util::byteOp(WGF, WEF, "XOR", kappa);
  CryptoPP::byte *encT = Util::byteOp(encF, r, "XOR", kappa);

  addGate(outputGate, "AND", inputGateL, inputGateR, encF, encT);
}

pair<CryptoPP::byte*, CryptoPP::byte*> HalfCircuit::getConstEnc() {
  pair<CryptoPP::byte*, CryptoPP::byte*> output;
  output.first = gatesEvaluated[CONST_ZERO];
  output.second = gatesEvaluated[CONST_ONE];
  return output;
}

GarbledCircuit* HalfCircuit::exportCircuit() {
  GarbledCircuit *F = new GarbledCircuit();
  F->setKappa(kappa);
  F->setOutputGates(outputGates);
  F->setGateOrder(gateOrder);
  F->setGateInfo(gateInfo);
  F->setConstants(getConstEnc());
  F->setDecodings(getDecodings());
  F->setAndEncodings(andEncodings);
  return F;
}

map<string, vector<CryptoPP::byte*>> HalfCircuit::getAndEncodings() {
  return andEncodings;
}

string HalfCircuit::toString() {
  return "Half circuit";
}


