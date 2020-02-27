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
  Splits a string and put them in a vector
*/
vector<string> CircuitReader::splitString(string s) {
  vector<string> output;
  boost::split(output, s, [](char c) {return c == ' ';});
  return output;
}

/*
  The circuit reader imports the file as a circuit.
  The boolean determines if it was successful
  The vector contains the input encodings
*/
pair<bool, vector<vector<CryptoPP::byte*>>> CircuitReader::import(CircuitInterface* c, string filename) {
  pair<bool, vector<vector<CryptoPP::byte*>>> output;
  string line;
  vector<string> data;
  vector<vector<CryptoPP::byte*>> inputEncs;
  string filepath = "circuits/"+filename;

  ifstream reader;
  reader.open(filepath);
  if(reader.is_open()) {
    regex r("[0-9]+");
    smatch m;

    //first line
    line = readOneLine(reader);
    data = splitString(line);
    int totalNrGates = stoi(data[0]);
    int totalNrWires = stoi(data[1]);

    //second line
    line = readOneLine(reader);
    data = splitString(line);
    int nrInputValues = stoi(data[0]);
    int totalInputGates = 0;
    vector<int> inputList;
    for(int i=0; i<nrInputValues; i++) {
      int v = stoi(data[i+1]);
      totalInputGates += v;
      inputList.push_back(v);
    }

    //third line
    line = readOneLine(reader);
    data = splitString(line);
    int nrOutputValues = stoi(data[0]);
    int totalOutputGates = 0;
    vector<int> outputList;
    for(int i=0; i<nrOutputValues; i++) {
      int v = stoi(data[i+1]);
      totalOutputGates += v;
      outputList.push_back(v);
    }

    //fourth line (empty)
    readOneLine(reader);

    //adds input gates
    for(int i=0; i<totalInputGates; i++) {
      string gateName = "w"+to_string(i);
      vector<CryptoPP::byte*> inputEnc = c->addGate(gateName);
      inputEncs.push_back(inputEnc);
    }

    //adds remaining gates
    int i = totalInputGates;
    while (!reader.eof()) {
      getline(reader, line);

      if(line.compare("") == 0) {
        break;
      } else {
        i++;
      }

      string gateName = "w"+to_string(i);
      data = splitString(line);

      int nrInputWires = stoi(data[0]);
      int nrOutputWires = stoi(data[1]);

      vector<int> inputWires;
      for(int j=0; j<nrInputWires; j++) {
        inputWires.push_back(stoi(data[j+2]));
      }

      vector<int> outputWires;
      for(int j=0; j<nrOutputWires; j++) {
        outputWires.push_back(stoi(data[j+nrInputWires+2]));
      }

      string gateType = data[nrInputWires+nrOutputWires+2];

      if(gateType.compare("XOR") == 0) {
        string gateL = "w"+to_string(inputWires[0]);
        string gateR = "w"+to_string(inputWires[1]);
        string gateO = "w"+to_string(outputWires[0]);
        c->addXOR(gateL, gateR, gateO);
      } else if(gateType.compare("AND") == 0) {
        string gateL = "w"+to_string(inputWires[0]);
        string gateR = "w"+to_string(inputWires[1]);
        string gateO = "w"+to_string(outputWires[0]);
        c->addAND(gateL, gateR, gateO);
      } else {
        cout << "Error! Unknown gate type: '" << gateType << "'" << endl;
        inputEncs.clear();
        output.first = false;
        output.second = inputEncs;
        return output;
      }
    }

    //Output gates
    vector<string> outputGates;
    for(int j=0; j<totalOutputGates; j++) {
      string gateName = "w"+to_string(i-totalOutputGates+j);
      outputGates.push_back(gateName);
    }
    c->setOutputGates(outputGates);
  }
  reader.close();

  output.first = true;
  output.second = inputEncs;
  return output;
}
