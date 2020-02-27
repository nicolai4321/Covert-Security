#ifndef CIRCUITREADER_H
#define CIRCUITREADER_H
#include <iostream>
#include <fstream>
#include <regex>
#include <string>
#include "CircuitInterface.h"
#include <boost/algorithm/string.hpp>
using namespace std;

class CircuitReader {
  public:
    CircuitReader();
    virtual ~CircuitReader();
    vector<string> splitString(string s);
    pair<bool, vector<vector<CryptoPP::byte*>>> import(CircuitInterface* c, string filename);

  protected:

  private:
    string readOneLine(ifstream& reader);
};

#endif // CIRCUITREADER_H
