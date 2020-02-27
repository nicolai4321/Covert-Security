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
    return addGate(gateName, "input", "", "");
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
  XOR-gate
*/
void GarbledCircuit::addXOR(string inputGateL, string inputGateR, string outputGate) {
  if(canEdit) {
    addGate(outputGate, "xor", inputGateL, inputGateR);

    CryptoPP::byte *falseEncodingL = gates[inputGateL].at(0);
    CryptoPP::byte *trueEncodingR = gates[inputGateR].at(1);

    CryptoPP::byte *falseEncodingR = gates[inputGateR].at(0);
    CryptoPP::byte *trueEncodingL = gates[inputGateL].at(1);

    CryptoPP::byte *falseEncodingO = gates[outputGate].at(0);
    CryptoPP::byte *trueEncodingO = gates[outputGate].at(1);

    vector<string> garbledTable;
    garbledTable.push_back(doubleEncrypt(falseEncodingO, falseEncodingL, falseEncodingR, iv));
    garbledTable.push_back(doubleEncrypt(trueEncodingO, falseEncodingL, trueEncodingR, iv));
    garbledTable.push_back(doubleEncrypt(trueEncodingO, trueEncodingL, falseEncodingR, iv));
    garbledTable.push_back(doubleEncrypt(falseEncodingO, trueEncodingL, trueEncodingR, iv));

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
    addGate(outputGate, "and", inputGateL, inputGateR);

    CryptoPP::byte *falseEncodingL = gates[inputGateL].at(0);
    CryptoPP::byte *trueEncodingR = gates[inputGateR].at(1);

    CryptoPP::byte *falseEncodingR = gates[inputGateR].at(0);
    CryptoPP::byte *trueEncodingL = gates[inputGateL].at(1);

    CryptoPP::byte *falseEncodingO = gates[outputGate].at(0);
    CryptoPP::byte *trueEncodingO = gates[outputGate].at(1);

    vector<string> garbledTable;
    garbledTable.push_back(doubleEncrypt(falseEncodingO, falseEncodingL, falseEncodingR, iv));
    garbledTable.push_back(doubleEncrypt(falseEncodingO, falseEncodingL, trueEncodingR, iv));
    garbledTable.push_back(doubleEncrypt(falseEncodingO, trueEncodingL, falseEncodingR, iv));
    garbledTable.push_back(doubleEncrypt(trueEncodingO, trueEncodingL, trueEncodingR, iv));

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

        if(gateType.compare("input") == 0) {
          gatesEvaluated[gateName] = inputs.at(i);
          i++;
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
