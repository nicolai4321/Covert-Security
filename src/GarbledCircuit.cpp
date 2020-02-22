#include <iostream>
#include "GarbledCircuit.h"
#include "Util.h"
#include <string>
#include <vector>
#include <map>
using namespace std;

GarbledCircuit::GarbledCircuit(int k) {
  kappa = k;
  iv = Util::generateIV();
}

/*
  Adds a new gate and names it with gateName and adds two encodings
  for false and true
*/
vector<CryptoPP::byte*> GarbledCircuit::addGate(string gateName) {
  return addGate(gateName, "input", "", "");
}

vector<CryptoPP::byte*> GarbledCircuit::addGate(string gateName, string gateType, string gateL, string gateR) {
  CryptoPP::byte *encF = Util::randomByte(kappa);
  CryptoPP::byte *encT = Util::randomByte(kappa);

  vector<CryptoPP::byte*> encodings;
  encodings.push_back(encF);
  encodings.push_back(encT);
  gates[gateName] = encodings;

  gatesOutput.clear();
  gatesOutput.push_back(encF);
  gatesOutput.push_back(encT);

  //TODO permute

  vector<string> info;
  info.push_back(gateType);
  info.push_back(gateL);
  info.push_back(gateR);
  gateInfo[gateName] = info;

  gateOrder.push_back(gateName);
  return encodings;
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
  XOR gate
*/
void GarbledCircuit::addXOR(string inputGateL, string inputGateR, string outputGate) {
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
  garbledTables[outputGate] = garbledTable;

  //TODO permute
}

/*
  Evaluate input
*/
void GarbledCircuit::evaluateInput(vector<CryptoPP::byte*> inputs, int i, string gateName) {
  gatesEvaluated[gateName] = inputs.at(i);
}

/*
  Evaluate xor
*/
void GarbledCircuit::evaluateXOR(string gateL, string gateR, string gateName) {
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

  if(validEncodings.size() == 1) {
    gatesEvaluated[gateName] = validEncodings.at(0);
  } else {
    string msg = "Error! Invalid evaluation of xor-gate";
    Util::printl(msg);
    throw msg;
  }
}

/*
  Returns the decoding of the output.
  The first bool determines if the decoding was successful
  The second bool determines the output value
*/
pair<bool, bool> GarbledCircuit::decode(CryptoPP::byte* enc) {
  pair<bool, bool> output;
  if(memcmp(enc, gatesOutput.at(0), kappa) == 0) {
    output.first = true;
    output.second = false;
  } else if(memcmp(enc, gatesOutput.at(1), kappa) == 0) {
    output.first = true;
    output.second = true;
  } else {
    output.first = false;
    output.second = false;
  }
  return output;
}

/*
  Evaluates the circuit and returns a pair
  the first index is true if the evaluation was successful
  the second index is the output encoding if the evaluation was succesful
*/
pair<bool, CryptoPP::byte*> GarbledCircuit::evaluate(vector<CryptoPP::byte*> inputs) {
  pair<bool, CryptoPP::byte*> output;

  try {
    int i=0;
    for(string gateName : gateOrder) {
      vector<string> info = gateInfo[gateName];
      string gateType = info.at(0);
      string gateL = info.at(1);
      string gateR = info.at(2);

      if(gateType.compare("input") == 0) {
        evaluateInput(inputs, i, gateName);
        i++;
      } else if(gateType.compare("xor") == 0) {
        evaluateXOR(gateL, gateR, gateName);
      }
    }

    string lastGate = gateOrder.at(gateOrder.size()-1);
    CryptoPP::byte *encodingOutput = gatesEvaluated[lastGate];
    output.first = true;
    output.second = encodingOutput;
  } catch (...) {
    Util::printl("Error! Could not evaluate circuit");
    output.first = false;
    output.second = Util::randomByte(kappa);
  }

  return output;
}
