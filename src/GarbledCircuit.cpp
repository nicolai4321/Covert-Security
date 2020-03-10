#include "GarbledCircuit.h"
using namespace std;

GarbledCircuit::GarbledCircuit(int k, unsigned int s) {
  kappa = k;
  seed = s;
}

GarbledCircuit::~GarbledCircuit() {}

CircuitInterface* GarbledCircuit::createInstance(int kappa, int seed) {
  return new GarbledCircuit(kappa, seed);
}

string GarbledCircuit::toString() {
  return "Normal garbled circuit";
}

/*
  Adds a new gate and names it with gateName and adds two encodings
  for false and true
*/
vector<CryptoPP::byte*> GarbledCircuit::addGate(string gateName) {
  if(canEdit) {
    return addGate(gateName, "INPUT", "", "");
  } else {
    Util::printl("Error! Circuit cannot be modified");
    return vector<CryptoPP::byte*>();
  }
}

/*
  Adds a new gate and names it with gateName and adds two encodings
  for false and true
*/
vector<CryptoPP::byte*> GarbledCircuit::addGate(string gateName, string gateType, string gateL, string gateR) {
  if(canEdit) {
    CryptoPP::byte *encF = Util::randomByte(kappa, seed); seed++;
    CryptoPP::byte *encT = Util::randomByte(kappa, seed); seed++;

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
  } else {
    Util::printl("Error! Circuit cannot be modified");
    return vector<CryptoPP::byte*>();
  }
}

/*
  Encodes the gate: H(W_l || W_r) xor (W_o || 0^k)
*/
CryptoPP::byte* GarbledCircuit::encodeGate(CryptoPP::byte* encL, CryptoPP::byte* encR, CryptoPP::byte* encO) {
  CryptoPP::byte *zero = new CryptoPP::byte[kappa];
  memset(zero, 0x00, kappa);

  CryptoPP::byte *l = Util::h(Util::mergeBytes(encL, encR, kappa), 2*kappa);
  CryptoPP::byte *r = Util::mergeBytes(encO, zero, kappa);
  return Util::byteOp(l, r, "XOR", 2*kappa);
}

/*
  Decodes a gate if the last characters are zeros
*/
pair<bool, CryptoPP::byte*> GarbledCircuit::decodeGate(CryptoPP::byte* encL, CryptoPP::byte* encR, CryptoPP::byte* enc) {
  pair<bool, CryptoPP::byte*> output;
  CryptoPP::byte *l = Util::h(Util::mergeBytes(encL, encR, kappa), 2*kappa);
  CryptoPP::byte *decoded = Util::byteOp(l, enc, "XOR", 2*kappa);

  CryptoPP::byte *zero = new CryptoPP::byte[kappa];
  memset(zero, 0x00, kappa);

  CryptoPP::byte *left = new CryptoPP::byte[kappa];
  CryptoPP::byte *right = new CryptoPP::byte[kappa];
  left = decoded;
  right = (decoded+kappa);

  if(memcmp(right, zero, kappa) == 0) {
    output.first = true;
    output.second = left;
    return output;
  } else {
    output.first = false;
    output.second = zero;
    return output;
  }
}

/*
  EQ
*/
void GarbledCircuit::addEQ(bool b, string outputGate) {
  if(canEdit) {
    constCounter++;
    string gateConst = "const"+to_string(constCounter);
    vector<CryptoPP::byte*> encs = addGate(gateConst, "CONST", "", "");
    gatesEvaluated[gateConst] = (b) ? encs.at(1) : encs.at(0);
    addEQW(gateConst, outputGate);
  }
}

/*
  EQW-gate
*/
void GarbledCircuit::addEQW(string inputGate, string outputGate) {
  if(canEdit) {
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
}

/*
  INV-gate
*/
void GarbledCircuit::addINV(string inputGate, string outputGate) {
  if(canEdit) {
    constCounter++;
    string constGate = "const"+to_string(constCounter);
    vector<CryptoPP::byte*> encs = addGate(constGate, "CONST", "", "");
    gatesEvaluated[constGate] = encs.at(1);
    addGate(outputGate, "XOR", inputGate, constGate);

    CryptoPP::byte *encFL = gates[inputGate].at(0);
    CryptoPP::byte *encTL = gates[inputGate].at(1);

    CryptoPP::byte *encTR = gates[constGate].at(1);

    CryptoPP::byte *encFO = gates[outputGate].at(0);
    CryptoPP::byte *encTO = gates[outputGate].at(1);

    vector<CryptoPP::byte*> garbledTable;
    garbledTable.push_back(encodeGate(encFL, encTR, encTO));
    garbledTable.push_back(encodeGate(encTL, encTR, encFO));
    asrp.Shuffle(garbledTable.begin(), garbledTable.end());
    garbledTables[outputGate] = garbledTable;
  }
}

/*
  XOR-gate
*/
void GarbledCircuit::addXOR(string inputGateL, string inputGateR, string outputGate) {
  if(canEdit) {
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
}

/*
  AND-gate
*/
void GarbledCircuit::addAND(string inputGateL, string inputGateR, string outputGate) {
  if(canEdit) {
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
}

/*
  Evaluate normal gate
*/
void GarbledCircuit::evaluateGate(string gateL, string gateR, string gateName) {
  vector<CryptoPP::byte*> garbledTable = garbledTables[gateName];
  CryptoPP::byte *encL = gatesEvaluated[gateL];
  CryptoPP::byte *encR = gatesEvaluated[gateR];
  CryptoPP::byte *output0 = gates[gateName].at(0);
  CryptoPP::byte *output1 = gates[gateName].at(1);

  vector<CryptoPP::byte*> validEncodings;
  for(CryptoPP::byte *b : garbledTable) {
    pair<bool, CryptoPP::byte*> result = decodeGate(encL, encR, b);
    if(result.first) {
      validEncodings.push_back(result.second);
    }
  }

  //check that only one encoding was valid
  if(validEncodings.size() == 1) {
    gatesEvaluated[gateName] = validEncodings.at(0);
  } else if (validEncodings.size() > 1) {
    string msg = "Error! Multiple valid encodings";
    Util::printl(msg);
    throw msg;
  } else {
    string msg = "Error! No valid encodings";
    Util::printl(msg);
    throw msg;
  }
}

/*
  Evaluates the circuit and returns a pair
  the boolean is true if the evaluation was successful
  the vector is the output encodings if the evaluation was succesful
*/
pair<bool, vector<CryptoPP::byte*>> GarbledCircuit::evaluate(vector<CryptoPP::byte*> inputs) {
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
        } else {
          evaluateGate(gateL, gateR, gateName);
        }
      }

      //output gates
      for(string gateName : gatesOutput) {
        CryptoPP::byte *encoded = gatesEvaluated[gateName];
        bytes.push_back(encoded);
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
