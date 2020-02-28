#include "GarbledCircuit.h"
using namespace std;

GarbledCircuit::GarbledCircuit(int k) {
  kappa = k;
  iv = Util::generateIV();
}

GarbledCircuit::~GarbledCircuit() {}

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
    CryptoPP::byte *encF = Util::randomByte(kappa);
    CryptoPP::byte *encT = Util::randomByte(kappa);

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
    return encodings;
  } else {
    Util::printl("Error! Circuit cannot be modified");
    return vector<CryptoPP::byte*>();
  }
}

/*
  Encryption: E(keyL, iv, E(keyR, iv, m))
*/
string GarbledCircuit::doubleEncrypt(CryptoPP::byte* m, CryptoPP::byte* keyL, CryptoPP::byte* keyR, CryptoPP::byte* iv) {
  string msg = Util::byteToString(m, kappa);
  string cipherText0 = Util::encrypt(msg, keyR, iv);
  string cipherText1 = Util::encrypt(cipherText0, keyL, iv);
  return cipherText1;
}

/*
  Decryption: D(keyR, iv, D(keyL, iv, c))
*/
CryptoPP::byte* GarbledCircuit::doubleDecrypt(string c, CryptoPP::byte* keyL, CryptoPP::byte* keyR, CryptoPP::byte* iv) {
  string clearText0 = Util::decrypt(c, keyL, iv);
  string clearText1 = Util::decrypt(clearText0, keyR, iv);
  CryptoPP::byte *clearTextB = Util::stringToByte(clearText1, kappa);
  return clearTextB;
}

/*
  EQ
*/
void GarbledCircuit::addEQ(bool b, string outputGate) {
  if(canEdit) {
    string gateConst = "const"+outputGate;
    addGate(gateConst, "CONST", "", "");
    gatesEvaluated[gateConst] = (b) ? gates[gateConst].at(1) : gates[gateConst].at(0);
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

    vector<string> garbledTable;
    garbledTable.push_back(doubleEncrypt(encFO, encF, encF, iv));
    garbledTable.push_back(doubleEncrypt(encTO, encT, encT, iv));

    //Permutation
    CryptoPP::AutoSeededRandomPool asrp;
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
    string constGate = "const"+constCounter;
    vector<CryptoPP::byte*> encs = addGate(constGate, "CONST", "", "");
    gatesEvaluated[constGate] = encs.at(1);
    addGate(outputGate, "XOR", inputGate, constGate);

    CryptoPP::byte *encFL = gates[inputGate].at(0);
    CryptoPP::byte *encTL = gates[inputGate].at(1);

    CryptoPP::byte *encTR = gates[constGate].at(1);

    CryptoPP::byte *encFO = gates[outputGate].at(0);
    CryptoPP::byte *encTO = gates[outputGate].at(1);

    vector<string> garbledTable;
    garbledTable.push_back(doubleEncrypt(encTO, encFL, encTR, iv));
    garbledTable.push_back(doubleEncrypt(encFO, encTL, encTR, iv));

    //permutation
    CryptoPP::AutoSeededRandomPool asrp;
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

    vector<string> garbledTable;
    garbledTable.push_back(doubleEncrypt(encFO, encFL, encFR, iv));
    garbledTable.push_back(doubleEncrypt(encTO, encFL, encTR, iv));
    garbledTable.push_back(doubleEncrypt(encTO, encTL, encFR, iv));
    garbledTable.push_back(doubleEncrypt(encFO, encTL, encTR, iv));

    //permutation
    CryptoPP::AutoSeededRandomPool asrp;
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

    vector<string> garbledTable;
    garbledTable.push_back(doubleEncrypt(encFO, encFL, encFR, iv));
    garbledTable.push_back(doubleEncrypt(encFO, encFL, encTR, iv));
    garbledTable.push_back(doubleEncrypt(encFO, encTL, encFR, iv));
    garbledTable.push_back(doubleEncrypt(encTO, encTL, encTR, iv));

    //permutation
    CryptoPP::AutoSeededRandomPool asrp;
    asrp.Shuffle(garbledTable.begin(), garbledTable.end());

    garbledTables[outputGate] = garbledTable;
  }
}

/*
  Evaluate normal gate
*/
void GarbledCircuit::evaluateGate(string gateL, string gateR, string gateName) {
  vector<string> garbledTable = garbledTables[gateName];
  CryptoPP::byte *keyL = gatesEvaluated[gateL];
  CryptoPP::byte *keyR = gatesEvaluated[gateR];
  CryptoPP::byte *output0 = gates[gateName].at(0);
  CryptoPP::byte *output1 = gates[gateName].at(1);

  vector<CryptoPP::byte*> validEncodings;
  for(string c : garbledTable) {
    try {
      CryptoPP::byte *enc = doubleDecrypt(c, keyL, keyR, iv);

      if(memcmp(enc, output0, kappa) == 0 || memcmp(enc, output1, kappa) == 0) {
        validEncodings.push_back(enc);
      }
    } catch (...) {
        //ignore invalud encodings
    }
  }

  //check that only one encoding was valid
  if(validEncodings.size() == 1) {
    gatesEvaluated[gateName] = validEncodings.at(0);
  } else {
    string msg = "Error! Invalid evaluation of gate";
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
