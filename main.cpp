#include "CircuitInterface.h"
#include "CircuitReader.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Network/IOService.h"
#include "cryptoTools/Network/SocketAdapter.h"
#include "cryptlib.h"
#include "EvaluatorHalf.h"
#include "EvaluatorInterface.h"
#include "EvaluatorNormal.h"
#include "fstream"
#include "GarbledCircuit.h"
#include "HalfCircuit.h"
#include "HashHardware.h"
#include "HashInterface.h"
#include "HashNormal.h"
#include "iostream"
#include "NormalCircuit.h"
#include "libOTe/TwoChooseOne/KosOtExtReceiver.h"
#include "libOTe/TwoChooseOne/KosOtExtSender.h"
#include "PartyA.h"
#include "PartyB.h"
#include "Signature.h"
#include "SocketRecorder.h"
#include "string"
#include "TimeLog.h"
#include "Util.h"
using namespace std;
using namespace std::chrono;

/*
  Runs a circuit from a file and checks that the amount of
  input is correct, the circuit can be evaluated and that
  the encoding can be decoded. The time for the evaluation
  is returned
*/
double runCircuit(CircuitInterface* circuit, EvaluatorInterface* evaluator, int kappa, string filename, string input) {
  try {
    CircuitReader cr = CircuitReader();
    pair<bool, vector<vector<CryptoPP::byte*>>> import = cr.import(circuit, filename);
    int inputGatesNr = cr.getInputGates();

    if(!import.first) {
      string msg = "Error! Could not import circuit";
      cout << msg << endl;
      throw msg;
    }

    clock_t start = clock();

    vector<vector<CryptoPP::byte*>> encodings = import.second;
    vector<CryptoPP::byte*> inputs;
    int i=0;
    for(char c : input) {
      if(i == inputGatesNr) {
        string msg = "Error! To many input gates. There are only "+to_string(inputGatesNr)+" input gates";
        cout << msg << endl;
        throw msg;
      }
      int b = (int) c - 48;
      inputs.push_back(encodings.at(i).at(b));
      i++;
    }

    if(i != inputGatesNr) {
        string msg = "Error! To few input gates. There should be "+to_string(inputGatesNr)+" input gates";
        cout << msg << endl;
        throw msg;
    }

    GarbledCircuit *F = circuit->exportCircuit();
    evaluator->giveCircuit(F);
    pair<bool, vector<CryptoPP::byte*>> evaluation = evaluator->evaluate(inputs);
    if(evaluation.first) {
      vector<CryptoPP::byte*> Z = evaluation.second;
      pair<bool, vector<bool>> decoded = evaluator->decode(Z);

      if(decoded.first) {
        cout << "output: ";
        for(bool b : decoded.second) {
          cout << b;
        }
        cout << endl;

        double duration = (clock()-start) / (double) CLOCKS_PER_SEC;
        return duration;
      } else {
        string msg = "Error! Could not decode the encoding";
        cout << msg << endl;
        throw msg;
      }
    } else {
      string msg = "Error! Could not evaluate circuit";
      cout << msg << endl;
      throw msg;
    }
  } catch (...) {
    return 0;
  }
}

/*
  Runs the circuit files
*/
void runCircuitFiles(int kappa, HashInterface *hashInterface) {
  CryptoPP::byte *seed = Util::randomByte(kappa);
  string files[8] = {"adder64.txt", "divide64.txt", "udivide.txt", "mult64.txt", "mult2_64.txt", "sub64.txt", "neg64.txt", "zero_equal.txt"};

  double timeTotal0 = 0;
  double timeTotal1 = 0;

  for(string filename : files) {
    string i0 = "0101000000000000000000000000000000000000000000000000000000000000"; //10
    string i1 = "0100000000000000000000000000000000000000000000000000000000000000"; //2

    cout << filename << endl;
    cout << "Input: " << i0;
    string input = "";
    input += i0;
    if(filename.compare("neg64.txt") != 0 && filename.compare("zero_equal.txt") != 0) {
      input += i1;
      cout << " | " << i1;
    }
    cout << endl;

    CircuitInterface *circuitN = new NormalCircuit(kappa, seed, hashInterface);
    CircuitInterface *circuitH = new HalfCircuit(kappa, seed, hashInterface);
    EvaluatorInterface *evalN = new EvaluatorNormal(hashInterface);
    EvaluatorInterface *evalH = new EvaluatorHalf(hashInterface);

    double time0 = runCircuit(circuitN, evalN, kappa, filename, input);
    double time1 = runCircuit(circuitH, evalH, kappa, filename, input);
    timeTotal0 += time0;
    timeTotal1 += time1;

    cout << "Time: " << time0 << " ("+circuitN->toString()+"), " << time1 << " ("+circuitH->toString()+")" << endl;
    cout << endl;
  }

  cout << "Time total: " << timeTotal0 << " (normal), " << timeTotal1 << " (half)" << endl;
}

bool startProtocol(int kappa, int lambda, int x, int y, CircuitInterface *circuit, EvaluatorInterface *evaluator) {
  //Digital Signature
  pair<CryptoPP::ESIGN<CryptoPP::Whirlpool>::PrivateKey, CryptoPP::ESIGN<CryptoPP::Whirlpool>::PublicKey> keys = Signature::generateKeys(64*3);
  CryptoPP::ESIGN<CryptoPP::Whirlpool>::PrivateKey sk = keys.first;
  CryptoPP::ESIGN<CryptoPP::Whirlpool>::PublicKey pk = keys.second;

  TimeLog *timeLog = new TimeLog();
  TimeLog *timeLogA = new TimeLog();
  TimeLog *timeLogB = new TimeLog();

  bool b0;
  bool b1;

  timeLog->markTime("protocol time");
  auto threadA = thread([&]() {
    PartyA partyA = PartyA(x, sk, pk, kappa, lambda, circuit, timeLogA);
    b0 = partyA.startProtocol();
 });
  auto threadB = thread([&]() {
    PartyB partyB = PartyB(y, pk, kappa, lambda, circuit, evaluator, timeLogB);
    b1 = partyB.startProtocol();
  });

  threadA.join();
  threadB.join();
  timeLog->endMark("protocol time");

  if(b0 && b1) {
    cout << circuit->toString() << ": success" << endl;
    string s = timeLog->getTimes();
    /*
    s += "\nA:\n";
    s += timeLogA->getTimes();
    s += "\nB:\n";
    s += timeLogB->getTimes();
    */

    bool saveToFile = false;
    if(saveToFile) {
      ofstream file(circuit->toString()+".txt");
      file << s;
    } else {
      cout << s << endl << endl;
    }

    return true;
  } else {
    cout << circuit->toString() << ": fail" << endl << endl;
    return false;
  }
}

void startProtocols(int kappa) {
  int lambda = 8;
  int x = 5;
  int y = 2;

  //HashInterfaces
  int keyLength = CryptoPP::AES::DEFAULT_KEYLENGTH;
  CryptoPP::byte *key = Util::randomByte(keyLength);
  HashInterface *hashSha = new HashNormal(kappa);
  HashInterface *hashHardware = new HashHardware(key, keyLength);

  //Circuits
  CryptoPP::byte *unimportantSeed = Util::randomByte(kappa);

  //Normal circuit, sha hash
  CircuitInterface *normalCircuitSha = new NormalCircuit(kappa, unimportantSeed, hashSha);
  EvaluatorInterface *normalEvaluatorSha = new EvaluatorNormal(hashSha);
  startProtocol(kappa, lambda, x, y, normalCircuitSha, normalEvaluatorSha);

  //Half garbling, sha hash
  CircuitInterface *halfCircuitSha = new HalfCircuit(kappa, unimportantSeed, hashSha);
  EvaluatorInterface *halfEvaluatorSha = new EvaluatorHalf(hashSha);
  startProtocol(kappa, lambda, x, y, halfCircuitSha, halfEvaluatorSha);

  //Half garbling, aes hash
  CircuitInterface *halfCircuitAES = new HalfCircuit(kappa, unimportantSeed, hashHardware);
  EvaluatorInterface *halfEvaluatorAES = new EvaluatorHalf(hashHardware);
  startProtocol(kappa, lambda, x, y, halfCircuitAES, halfEvaluatorAES);
}

void timeHash(HashInterface *hashInter, int length, int rounds, string name) {
  CryptoPP::byte *plain = Util::randomByte(length);

  clock_t start = clock();
  for(int i=0; i<rounds; i++) {
    hashInter->hashByte(plain, length);
  }
  double duration = (clock()-start) / (double) CLOCKS_PER_SEC;
  cout << "time: " << duration << " - " << name << endl;
}

void runHashFuncs(int kappa, int rounds) {
  int keyLength = CryptoPP::AES::DEFAULT_KEYLENGTH;

  HashInterface *hashNormal = new HashNormal(kappa);
  timeHash(hashNormal, kappa, rounds, "normal");

  CryptoPP::byte *key = Util::randomByte(keyLength);
  HashInterface *hashHard = new HashHardware(key, keyLength);
  timeHash(hashHard, kappa, rounds, "aes hardware");
}

int main() {
  cout << "covert start" << endl;

  int kappa = 16; //they use 16 bytes, 16*8=128 bits

  //runCircuitFiles(kappa, hashInterface);
  startProtocols(kappa);
  //runHashFuncs(kappa, 1000000);

  cout << "covert end" << endl;
  return 0;
}
