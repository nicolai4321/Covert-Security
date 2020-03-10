#include "HalfCircuit.h"
using namespace std;

HalfCircuit::HalfCircuit(int k, unsigned int s) {
  kappa = k;
  seed = s;
  r = Util::randomByte(kappa, seed); seed++;

  //Ensuring that the last bit in r is 1
  unsigned char b = (unsigned char) 1;
  r[kappa-1] = r[kappa-1] | b;
}

HalfCircuit::~HalfCircuit() {}

CircuitInterface* HalfCircuit::createInstance(int kappa, int seed) {
  return new HalfCircuit(kappa, seed);
}


string HalfCircuit::toString() {
  return "Half garbled circuit";
}


/*
  Adds a new gate and names it with gateName and adds two encodings
  for false and true
*/
vector<CryptoPP::byte*> HalfCircuit::addGate(string gateName) {
  if(canEdit) {
    CryptoPP::byte *encF = Util::randomByte(kappa, seed); seed++;
    CryptoPP::byte *encT = Util::byteOp(encF, r, "XOR", kappa);
    return addGate(gateName, "INPUT", "", "", encF, encT);
  } else {
    Util::printl("Error! Circuit cannot be modified");
    return vector<CryptoPP::byte*>();
  }
}

/*
  Adds a new gate and names it with gateName and adds two encodings
  for false and true
*/
vector<CryptoPP::byte*> HalfCircuit::addGate(string gateName, string gateType, string gateL, string gateR, CryptoPP::byte *encF, CryptoPP::byte *encT) {
  if(canEdit) {
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
  } else {
    Util::printl("Error! Circuit cannot be modified");
    return vector<CryptoPP::byte*>();
  }
}

/*
  EQ-gate
*/
void HalfCircuit::addEQ(bool b, string outputGate) {
  if(canEdit) {
    constCounter++;
    string gateName = "const"+to_string(constCounter);
    CryptoPP::byte *encF = Util::randomByte(kappa, seed); seed++;
    CryptoPP::byte *encT = Util::byteOp(encF, r, "XOR", kappa);
    vector<CryptoPP::byte*> encs = addGate(gateName, "CONST", "", "", encF, encT);
    gatesEvaluated[gateName] = (b) ? encs.at(1) : encs.at(0);

    addEQW(gateName, outputGate);
  }
}

/*
  EQW-gate
*/
void HalfCircuit::addEQW(string inputGate, string outputGate) {
  if(canEdit) {
    constCounter++;
    string gateConst = "const"+to_string(constCounter);
    CryptoPP::byte *encFC = Util::randomByte(kappa, seed); seed++;
    CryptoPP::byte *encTC = Util::byteOp(encFC, r, "XOR", kappa);
    vector<CryptoPP::byte*> encs = addGate(gateConst, "CONST", "", "", encFC, encTC);
    gatesEvaluated[gateConst] = encs.at(0);

    CryptoPP::byte *encF = Util::byteOp(gates[inputGate].at(0), gates[gateConst].at(0), "XOR", kappa);
    CryptoPP::byte *encT = Util::byteOp(encF, r, "XOR", kappa);
    addGate(outputGate, "XOR", inputGate, gateConst, encF, encT);
  }
}

/*
  INV-gate
*/
void HalfCircuit::addINV(string inputGate, string outputGate) {
  if(canEdit) {
    constCounter++;
    string gateConst = "const"+to_string(constCounter);
    CryptoPP::byte *encFC = Util::randomByte(kappa, seed); seed++;
    CryptoPP::byte *encTC = Util::byteOp(encFC, r, "XOR", kappa);
    vector<CryptoPP::byte*> encs = addGate(gateConst, "CONST", "", "", encFC, encTC);
    gatesEvaluated[gateConst] = encs.at(1);

    CryptoPP::byte *encF = Util::byteOp(gates[inputGate].at(0), gates[gateConst].at(0), "XOR", kappa);
    CryptoPP::byte *encT = Util::byteOp(encF, r, "XOR", kappa);
    addGate(outputGate, "XOR", inputGate, gateConst, encF, encT);
  }
}

/*
  XOR-gate
*/
void HalfCircuit::addXOR(string inputGateL, string inputGateR, string outputGate) {
  if(canEdit) {
    CryptoPP::byte *encF = Util::byteOp(gates[inputGateL].at(0), gates[inputGateR].at(0), "XOR", kappa);
    CryptoPP::byte *encT = Util::byteOp(encF, r, "XOR", kappa);
    addGate(outputGate, "XOR", inputGateL, inputGateR, encF, encT);
  }
}

/*
  AND-gate
*/
void HalfCircuit::addAND(string inputGateL, string inputGateR, string outputGate) {
  if(canEdit) {
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
}

/*
  Evaluates the circuit and returns a pair
  the boolean is true if the evaluation was successful
  the vector is the output encodings if the evaluation was succesful
*/
pair<bool, vector<CryptoPP::byte*>> HalfCircuit::evaluate(vector<CryptoPP::byte*> inputs) {
  pair<bool, vector<CryptoPP::byte*>> output;
  vector<CryptoPP::byte*> bytes;
  if(canEdit) {
    Util::printl("Error! Cannot evaluate before circuit is build");
    output.first = false;
    output.second = bytes;
  } else {
    try {
      int i=0;
      for(string gateName : gateOrder) {
        vector<string> info = gateInfo[gateName];
        string gateType = info.at(0);
        string gateL = info.at(1);
        string gateR = info.at(2);

        if(gateType.compare("INPUT") == 0) {
          if(nrInputGates == i) {
            Util::printl("Error! Wrong number of input gates");
            bytes.clear();
            output.first = false;
            output.second = bytes;
            return output;
          }

          gatesEvaluated[gateName] = inputs.at(i);
          i++;
        } else if(gateType.compare("CONST") == 0) {
        } else if(gateType.compare("XOR") == 0) {
          gatesEvaluated[gateName] = Util::byteOp(gatesEvaluated[gateL], gatesEvaluated[gateR], "XOR", kappa);
        } else if(gateType.compare("AND") == 0) {
          int sa = Util::lsb(gatesEvaluated[gateL], kappa);
          int sb = Util::lsb(gatesEvaluated[gateR], kappa);

          CryptoPP::byte *TG = andEncodings[gateName].at(0);
          CryptoPP::byte *TE = andEncodings[gateName].at(1);
          CryptoPP::byte *Wa = gatesEvaluated[gateL];
          CryptoPP::byte *Wb = gatesEvaluated[gateR];

          CryptoPP::byte *WG = (sa) ?
            Util::byteOp(Util::h(Wa, kappa), TG, "XOR", kappa):
            Util::h(Wa, kappa);

          CryptoPP::byte *WE = (sb) ?
            Util::byteOp(Util::h(Wb, kappa), Util::byteOp(TE, Wa, "XOR", kappa), "XOR", kappa):
            Util::h(Wb, kappa);

          gatesEvaluated[gateName] = Util::byteOp(WG, WE, "XOR", kappa);
        } else {
          Util::printl("Error! Invalid gate type");
          bytes.clear();
          output.first = false;
          output.second = bytes;
          return output;
        }
      }

      //gets the output
      for(string gateName : gatesOutput) {
        CryptoPP::byte *encodingOutput = gatesEvaluated[gateName];
        bytes.push_back(encodingOutput);
      }

      output.first = true;
      output.second = bytes;
    } catch (...) {
      Util::printl("Error! Could not evaluate circuit");
      bytes.clear();
      output.first = false;
      output.second = bytes;
    }
  }
  return output;
}
