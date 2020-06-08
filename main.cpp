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
    cr.setReverseInput(true);
    pair<bool, vector<vector<CryptoPP::byte*>>> import = cr.import(circuit, filename);
    int inputGatesNr = cr.getInputGates();

    if(!import.first) {throw runtime_error("Error! Could not import circuit");}
    clock_t start = clock();

    vector<vector<CryptoPP::byte*>> encodings = import.second;
    vector<CryptoPP::byte*> inputs;
    int i=0;
    for(char c : input) {
      if(i == inputGatesNr) {
        throw runtime_error("Error! To many input gates. There are only "+to_string(inputGatesNr)+" input gates");
      }
      int b = (int) c - 48;
      inputs.push_back(encodings.at(i).at(b));
      i++;
    }

    if(i != inputGatesNr) {throw runtime_error("Error! To few input gates. There should be "+to_string(inputGatesNr)+" input gates");}

    GarbledCircuit *F = new GarbledCircuit();
    circuit->exportCircuit(F);
    evaluator->giveCircuit(F);
    pair<bool, vector<CryptoPP::byte*>> evaluation = evaluator->evaluate(inputs);
    if(evaluation.first) {
      vector<CryptoPP::byte*> Z = evaluation.second;
      pair<bool, vector<bool>> decoded = evaluator->decode(Z);

      if(decoded.first) {
        cout << "output: ";

        for(int i=decoded.second.size()-1; i>=0; i--) {
          cout << decoded.second.at(i);
        }
        cout << endl;

        double duration = (clock()-start) / (double) CLOCKS_PER_SEC;
        return duration;
      } else {
        throw runtime_error("Error! Could not decode the encoding");
      }
    } else {
      throw runtime_error("Error! Could not evaluate circuit");
    }
    delete F;
  } catch (exception& e) {
    cout << e.what() << endl;
    return 0;
  }
}

/*
  Runs the circuit files
*/
void runCircuitFiles(int kappa) {
  CryptoPP::byte seed[kappa];
  CryptoPP::AutoSeededRandomPool asrp;
  asrp.GenerateBlock(seed, kappa);
  string files[8] = {"adder64.txt", "divide64.txt", "udivide.txt", "mult64.txt", "mult2_64.txt", "sub64.txt", "neg64.txt", "zero_equal.txt"};

  double timeTotal0 = 0;
  double timeTotal1 = 0;

  for(string filename : files) {
    string i0 = "0000000000000000000000000000000000000000000000000000000000001010"; //10
    string i1 = "0000000000000000000000000000000000000000000000000000000000000010"; //2

    cout << filename << endl;
    cout << "Input: " << i0;
    string input = "";
    input += i0;
    if(filename.compare("neg64.txt") != 0 && filename.compare("zero_equal.txt") != 0) {
      input += i1;
      cout << " | " << i1;
    }
    cout << endl;
    HashInterface *hashInterfaceN = new HashNormal(kappa);
    HashInterface *hashInterfaceH = new HashNormal(kappa);
    CircuitInterface *circuitN = new NormalCircuit(kappa, seed, hashInterfaceN);
    CircuitInterface *circuitH = new HalfCircuit(kappa, seed, hashInterfaceH);
    EvaluatorInterface *evalN = new EvaluatorNormal(hashInterfaceN);
    EvaluatorInterface *evalH = new EvaluatorHalf(hashInterfaceH);

    double time0 = runCircuit(circuitN, evalN, kappa, filename, input);
    double time1 = runCircuit(circuitH, evalH, kappa, filename, input);


    timeTotal0 += time0;
    timeTotal1 += time1;

    cout << "Time: " << time0 << " ("+circuitN->toString()+"), " << time1 << " ("+circuitH->toString()+")" << endl;
    cout << endl;

    delete evalN;
    delete evalH;
    delete circuitN;
    delete circuitH;
    delete hashInterfaceN;
    delete hashInterfaceH;
  }

  cout << "Time total: " << timeTotal0 << " (normal), " << timeTotal1 << " (half)" << endl;
}

bool startProtocol(int kappa,
                   int lambda,
                   int x,
                   int y,
                   CircuitInterface *circuitA,
                   CircuitInterface *circuitB,
                   EvaluatorInterface *evaluator,
                   CryptoPP::RSA::PrivateKey sk,
                   CryptoPP::RSA::PublicKey pk,
                   string filename) {

  TimeLog *timeLog = new TimeLog();
  TimeLog *timeLogA = new TimeLog();
  TimeLog *timeLogB = new TimeLog();
  bool b0;
  bool b1;

  timeLog->markTime("protocol time");
  auto threadA = thread([&]() {
    PartyA partyA = PartyA(x, sk, pk, kappa, lambda, circuitA, timeLogA);
    b0 = partyA.startProtocol(filename);
 });

  auto threadB = thread([&]() {
    PartyB partyB = PartyB(y, pk, kappa, lambda, circuitB, evaluator, timeLogB);
    b1 = partyB.startProtocol(filename);
  });

  threadA.join();
  threadB.join();
  timeLog->endMark("protocol time");

  if(b0 && b1) {
    cout << circuitA->toString() << ": success" << endl;
    string s = timeLog->getTimes();

    if(true) {
      s += "\nA:\n";
      s += timeLogA->getTimes();
      s += "\nB:\n";
      s += timeLogB->getTimes();
    }

    if(true) {
      ofstream file("time/"+circuitA->toString()+filename);
      file << s;
    }

    if(true) {
      cout << timeLog->getTimes() << endl << endl;
    }

    if(false) {
      cout << s << endl << endl;
    }

    return true;
  } else {
    cout << circuitA->toString() << ": fail" << endl << endl;
    return false;
  }
}

void startProtocols(string filename, int kappa, int lambda, int x, int y) {
  CryptoPP::AutoSeededRandomPool asrp;

  //Digital Signature
  pair<CryptoPP::RSA::PrivateKey, CryptoPP::RSA::PublicKey> keys = Signature::generateKeys(1024);
  CryptoPP::RSA::PrivateKey sk = keys.first;
  CryptoPP::RSA::PublicKey pk = keys.second;

  //HashInterfaces
  int keyLength = CryptoPP::AES::DEFAULT_KEYLENGTH;
  CryptoPP::byte key[keyLength];
  asrp.GenerateBlock(key, keyLength);

  HashInterface *hashShaA = new HashNormal(kappa);
  HashInterface *hashShaB = new HashNormal(kappa);

  //Circuits
  CryptoPP::byte unimportantSeed[kappa];
  asrp.GenerateBlock(unimportantSeed, kappa);

  //Normal circuit, sha hash
  CircuitInterface *normalCircuitShaA = new NormalCircuit(kappa, unimportantSeed, hashShaA);
  CircuitInterface *normalCircuitShaB = new NormalCircuit(kappa, unimportantSeed, hashShaB);
  EvaluatorInterface *normalEvaluatorSha = new EvaluatorNormal(hashShaB);
  startProtocol(kappa, lambda, x, y, normalCircuitShaA, normalCircuitShaB, normalEvaluatorSha, sk, pk, filename);

  //Free memory
  delete normalCircuitShaA;
  delete normalCircuitShaB;
  delete normalEvaluatorSha;

  //Half garbling, sha hash
  CircuitInterface *halfCircuitShaA = new HalfCircuit(kappa, unimportantSeed, hashShaA);
  CircuitInterface *halfCircuitShaB = new HalfCircuit(kappa, unimportantSeed, hashShaB);
  EvaluatorInterface *halfEvaluatorSha = new EvaluatorHalf(hashShaB);
  startProtocol(kappa, lambda, x, y, halfCircuitShaA, halfCircuitShaB, halfEvaluatorSha, sk, pk, filename);

  //Free memory
  delete halfCircuitShaA;
  delete halfCircuitShaB;
  delete halfEvaluatorSha;

  delete hashShaA;
  delete hashShaB;

  //Half garbling, aes hash
  HashInterface *hashHardwareA = new HashHardware(key, keyLength);
  HashInterface *hashHardwareB = new HashHardware(key, keyLength);

  CircuitInterface *halfCircuitAESA = new HalfCircuit(kappa, unimportantSeed, hashHardwareA);
  CircuitInterface *halfCircuitAESB = new HalfCircuit(kappa, unimportantSeed, hashHardwareB);
  EvaluatorInterface *halfEvaluatorAES = new EvaluatorHalf(hashHardwareB);
  startProtocol(kappa, lambda, x, y, halfCircuitAESA, halfCircuitAESB, halfEvaluatorAES, sk, pk, filename);

  //Free memory
  delete halfCircuitAESA;
  delete halfCircuitAESB;
  delete halfEvaluatorAES;

  delete hashHardwareA;
  delete hashHardwareB;
}

double timeHash(CryptoPP::AutoSeededRandomPool *asrp, HashInterface *hashInter, int length, int rounds, string name) {
  CryptoPP::byte plain[length];
  asrp->GenerateBlock(plain, length);

  clock_t start = clock();
  for(int i=0; i<rounds; i++) {
    CryptoPP::byte hashedByte[length];
    hashInter->hashByte(plain, length, hashedByte, length);
  }
  double duration = (clock()-start) / (double) CLOCKS_PER_SEC;
  return duration;
  //cout << "time: " << duration << " - " << name << endl;
}

void runHashFuncs(int kappa, int rounds) {
  int keyLength = CryptoPP::AES::DEFAULT_KEYLENGTH;
  CryptoPP::AutoSeededRandomPool asrp;
  int avv = 1;

  HashInterface *hashNormal = new HashNormal(kappa);
  double timeNormal = 0;
  for(int i=0; i<avv; i++) {
    timeNormal += timeHash(&asrp, hashNormal, kappa, rounds, "normal");
  }
  cout << "time: " << timeNormal/avv << " - " << "normal" << endl;

  CryptoPP::byte key[keyLength];
  asrp.GenerateBlock(key, keyLength);
  delete hashNormal;

  HashInterface *hashHard = new HashHardware(key, keyLength);
  double timeAES = 0;
  for(int i=0; i<avv; i++) {
    timeAES += timeHash(&asrp, hashHard, kappa, rounds, "aes hardware");
  }
  cout << "time: " << timeAES/avv << " - " << "aes" << endl;
  delete hashHard;
}

/*
  The arguments are
  - filename
  - lambda
  - x
  - y
*/
int main(int argc, char* argv[]) {
  cout << "||COVERT START||" << endl;

  if(argc == 5){
    string filename = argv[1];
    int lambda = atoi(argv[2]);
    int x = atoi(argv[3]);
    int y = atoi(argv[4]);
    int kappa = 16; //they use 16 bytes, 16*8=128 bits

    cout << "filename: " << filename;
    cout << ", lambda: " << lambda;
    cout << ", x: " << x;
    cout << ", y: " << y;
    cout << ", n1: " << GV::n1;
    cout << ", n2: " << GV::n2;
    cout << ", kappa: " << kappa << endl << endl;

    startProtocols(filename, kappa, lambda, x, y);
  } else {
    cout << "need arguments for: file name, lambda, x and y" << endl;
  }

  //runCircuitFiles(kappa);8
  //runHashFuncs(kappa, 1000000);
  //runHashFuncs(kappa, 2^30);

  cout << "||COVERT END||" << endl;
  return 0;
}
