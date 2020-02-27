#ifndef CIRCUITREADER_H
#define CIRCUITREADER_H
#include <iostream>
#include <fstream>
#include <regex>
#include <string>
#include "CircuitInterface.h"
using namespace std;

class CircuitReader {
  public:
    CircuitReader();
    virtual ~CircuitReader();
    void import(CircuitInterface* c, string filename);

  protected:

  private:
    string readOneLine(ifstream& reader);
};

#endif // CIRCUITREADER_H
