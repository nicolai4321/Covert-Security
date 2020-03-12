#ifndef CIRCUITINFO_H
#define CIRCUITINFO_H
#include <map>
#include <string>
#include <vector>
#include "cryptlib.h"
using namespace std;

class GarbledCircuit {
  public:
    GarbledCircuit();
    virtual ~GarbledCircuit();
    void setKappa(int kappa);
    void setOutputGates(vector<string> outputGates);
    void setGateOrder(vector<string> gateOrder);
    void setGateInfo(map<string, vector<string>> gateInfo);
    void setConstants(pair<CryptoPP::byte*, CryptoPP::byte*> constEncs);
    void setAndEncodings(map<string, vector<CryptoPP::byte*>> andEncodings);
    void setGarbledTables(map<string, vector<CryptoPP::byte*>> garbledTables);
    void setDecodings(vector<vector<CryptoPP::byte*>> decodings);

    int getKappa();
    vector<string> getOutputGates();
    vector<string> getGateOrder();
    map<string, vector<string>> getGateInfo();
    pair<CryptoPP::byte*, CryptoPP::byte*> getConstants();
    map<string, vector<CryptoPP::byte*>> getAndEncodings();
    map<string, vector<CryptoPP::byte*>> getGarbledTables();
    vector<vector<CryptoPP::byte*>> getDecodings();

  protected:

  private:
    int kappa;
    vector<string> outputGates;
    vector<string> gateOrder;
    map<string, vector<string>> gateInfo;
    pair<CryptoPP::byte*, CryptoPP::byte*> constEncs;
    map<string, vector<CryptoPP::byte*>> andEncodings;
    map<string, vector<CryptoPP::byte*>> garbledTables;
    vector<vector<CryptoPP::byte*>> decodings;
};

#endif // CIRCUITINFO_H
