#include "CircuitReader.h"
using namespace std;

CircuitReader::CircuitReader() {}
CircuitReader::~CircuitReader() {}

/*
  The reader reads one line and returns the line as a string
*/
string CircuitReader::readOneLine(ifstream& reader) {
  string line;
  if(!reader.eof()) {
    getline(reader, line);
    return line;
  } else {
    return "";
  }
}

/*
  The circuit reader reads the file
*/
void CircuitReader::import(CircuitInterface* c, string filename) {
  string line;
  string filepath = "circuits/"+filename;

  ifstream reader;
  reader.open(filepath);
  if(reader.is_open()) {
    regex r("[0-9]+");
    smatch m;

    //first line
    line = readOneLine(reader);
    regex_search(line, m, r);
    int totalNrGates = stoi(m[0]);
    line = m.suffix().str();
    regex_search(line, m, r);
    int totalNrWires = stoi(m[0]);

    //second line
    line = readOneLine(reader);
    regex_search(line, m, r);
    int nrInputValues = stoi(m[0]);
    int totalInputGates = 0;
    vector<int> inputList;
    for(int i=0; i<nrInputValues; i++) {
      line = m.suffix().str();
      regex_search(line, m, r);
      int v = stoi(m[0]);
      inputList.push_back(v);
      totalInputGates += v;
    }

    //third line
    line = readOneLine(reader);
    regex_search(line, m, r);
    int nrOutputValues = stoi(m[0]);
    vector<int> outputList;
    for(int i=0; i<nrOutputValues; i++) {
      line = m.suffix().str();
      regex_search(line, m, r);
      outputList.push_back(stoi(m[0]));
    }

    //fourth line
    readOneLine(reader);

    cout << "#gates: " << totalNrGates << endl;
    cout << "#input gates: " << totalInputGates << endl;
    cout << "#wires: " << totalNrWires << " (including ouput wires for the circuit)" << endl;
    cout << "#input values: " << nrInputValues << endl;
    for(int i : inputList) {
      cout << "  " << i << endl;
    }
    cout << "#output values: " << nrOutputValues << endl;
    for(int i : outputList) {
      cout << "  " << i << endl;
    }

    //gates
    int gateNr = 0;
    while (!reader.eof()) {
      gateNr++;
      getline(reader, line);
      if(line.compare("") == 0) break;
      //cout << line << endl;
    }
  }
  reader.close();
}
