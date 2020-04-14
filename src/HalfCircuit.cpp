#include "HalfCircuit.h"
using namespace std;

CircuitInterface *HalfCircuit::createInstance(int k, CryptoPP::byte *s) {
  return new HalfCircuit(k, s, h);
}

/*
  Adds a new gate and names it with gateName and adds two encodings
  for false and true
*/
vector<CryptoPP::byte*> HalfCircuit::addGate(string gateName) {
  CryptoPP::byte *encF = new CryptoPP::byte[kappa];
  iv = Util::randomByte(encF, kappa, seed, kappa, iv);

  CryptoPP::byte *encT = new CryptoPP::byte[kappa];
  Util::byteOp(encF, r, encT, Util::XOR, kappa);

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
  CryptoPP::byte *encF = new CryptoPP::byte[kappa];
  CryptoPP::byte *encT = new CryptoPP::byte[kappa];
  Util::byteOp(gates[inputGate].at(0), gates[CONST_ZERO].at(0), encF, Util::XOR, kappa);
  Util::byteOp(encF, r, encT, Util::XOR, kappa);

  addGate(outputGate, "XOR", inputGate, CONST_ZERO, encF, encT);
}

/*
  INV-gate
*/
void HalfCircuit::addINV(string inputGate, string outputGate) {
  CryptoPP::byte *encF = new CryptoPP::byte[kappa];
  CryptoPP::byte *encT = new CryptoPP::byte[kappa];
  Util::byteOp(gates[inputGate].at(0), gates[CONST_ONE].at(0), encF, Util::XOR, kappa);
  Util::byteOp(encF, r, encT, Util::XOR, kappa);

  addGate(outputGate, "XOR", inputGate, CONST_ONE, encF, encT);
}

/*
  XOR-gate
*/
void HalfCircuit::addXOR(string inputGateL, string inputGateR, string outputGate) {
  CryptoPP::byte *encF = new CryptoPP::byte[kappa];
  CryptoPP::byte *encT = new CryptoPP::byte[kappa];
  Util::byteOp(gates[inputGateL].at(0), gates[inputGateR].at(0), encF, Util::XOR, kappa);
  Util::byteOp(encF, r, encT, Util::XOR, kappa);

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

  //WGF
  CryptoPP::byte hashLeftEnc[kappa];
  h->hashByte(leftEnc.at(pa), kappa, hashLeftEnc, kappa);

  CryptoPP::byte xorHashLeftEncR[kappa];
  Util::byteOp(hashLeftEnc, r, xorHashLeftEncR, Util::XOR, kappa);

  CryptoPP::byte *WGF = (pa*pb) ? xorHashLeftEncR : hashLeftEnc;

  //TG
  CryptoPP::byte hashWaf[kappa];
  CryptoPP::byte hashWat[kappa];
  h->hashByte(waf, kappa, hashWaf, kappa);
  h->hashByte(wat, kappa, hashWat, kappa);

  CryptoPP::byte xorHashWafWat[kappa];
  CryptoPP::byte xorHashWafWatR[kappa];
  Util::byteOp(hashWaf, hashWat, xorHashWafWat, Util::XOR, kappa);
  Util::byteOp(xorHashWafWat, r, xorHashWafWatR, Util::XOR, kappa);

  CryptoPP::byte *TG = new CryptoPP::byte[kappa];
  if(pb) {
    memcpy(TG, xorHashWafWatR, kappa);
  } else {
    memcpy(TG, xorHashWafWat, kappa);
  }

  //Evaluator part
  CryptoPP::byte *wbf = rightEnc.at(0);
  CryptoPP::byte *wbt = rightEnc.at(1);

  //WEF
  CryptoPP::byte WEF[kappa];
  h->hashByte(rightEnc.at(pb), kappa, WEF, kappa);

  //TE
  CryptoPP::byte hashWbf[kappa];
  CryptoPP::byte hashWbt[kappa];
  h->hashByte(wbf, kappa, hashWbf, kappa);
  h->hashByte(wbt, kappa, hashWbt, kappa);

  CryptoPP::byte xorHashWbfWbt[kappa];
  CryptoPP::byte *TE = new CryptoPP::byte[kappa];
  Util::byteOp(hashWbf, hashWbt, xorHashWbfWbt, Util::XOR, kappa);
  Util::byteOp(xorHashWbfWbt, waf, TE, Util::XOR, kappa);

  //Adding gates
  vector<CryptoPP::byte*> encodings;
  encodings.push_back(TG);
  encodings.push_back(TE);
  andEncodings[outputGate] = encodings;

  CryptoPP::byte *encF = new CryptoPP::byte[kappa];
  CryptoPP::byte *encT = new CryptoPP::byte[kappa];
  Util::byteOp(WGF, WEF, encF, Util::XOR, kappa);
  Util::byteOp(encF, r, encT, Util::XOR, kappa);

  addGate(outputGate, "AND", inputGateL, inputGateR, encF, encT);
}

pair<CryptoPP::byte*, CryptoPP::byte*> HalfCircuit::getConstEnc() {
  pair<CryptoPP::byte*, CryptoPP::byte*> output;
  output.first = gatesEvaluated[CONST_ZERO];
  output.second = gatesEvaluated[CONST_ONE];
  return output;
}

void HalfCircuit::exportCircuit(GarbledCircuit *F) {
  F->setKappa(kappa);
  F->setOutputGates(outputGates);
  F->setGateOrder(gateOrder);
  F->setGateInfo(gateInfo);
  F->setConstants(getConstEnc());
  F->setDecodings(getDecodings());
  F->setAndEncodings(andEncodings);
}

map<string, vector<CryptoPP::byte*>> HalfCircuit::getAndEncodings() {
  return andEncodings;
}

string HalfCircuit::toString() {
  return "Half circuit (hash: " + h->toString() + ")";
}

string HalfCircuit::getType() {
  return HalfCircuit::TYPE;
}

HalfCircuit::HalfCircuit(int k, CryptoPP::byte *s, HashInterface *hashInterface) {
  kappa = k;
  seed = s;
  r = new CryptoPP::byte[kappa];
  iv = Util::randomByte(r, kappa, seed, kappa, iv);
  h = hashInterface;

  //Ensuring that the lsb in r is 1
  unsigned char b = (unsigned char) 1;
  r[0] = r[0] | b;

  //Constant 0
  CryptoPP::byte *encFZ = new CryptoPP::byte[kappa];
  iv = Util::randomByte(encFZ, kappa, seed, kappa, iv);
  CryptoPP::byte *encTZ = new CryptoPP::byte[kappa];
  Util::byteOp(encFZ, r, encTZ, Util::XOR, kappa);
  vector<CryptoPP::byte*> encsZ = addGate(CONST_ZERO, "CONST", "", "", encFZ, encTZ);
  gatesEvaluated[CONST_ZERO] = encsZ.at(0);

  //Constant 1
  CryptoPP::byte *encFO = new CryptoPP::byte[kappa];
  iv = Util::randomByte(encFO, kappa, seed, kappa, iv);
  CryptoPP::byte *encTO = new CryptoPP::byte[kappa];
  Util::byteOp(encFO, r, encTO, Util::XOR, kappa);
  vector<CryptoPP::byte*> encsO = addGate(CONST_ONE, "CONST", "", "", encFO, encTO);
  gatesEvaluated[CONST_ONE] = encsO.at(1);
}

HalfCircuit::~HalfCircuit() {
  for(string gateName : gateOrder) {
    vector<CryptoPP::byte*> encs = gates[gateName];
    for(CryptoPP::byte *b : encs) {
      delete b;
    }

    vector<string> info = gateInfo[gateName];
    string gateType = info.at(0);

    if(gateType.compare("AND") == 0) {
      vector<CryptoPP::byte*> andEncs = andEncodings[gateName];
      for(CryptoPP::byte *b : andEncs) {
        delete b;
      }
    }
  }
  delete r;
}
