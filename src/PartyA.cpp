#include "PartyA.h"
using namespace std;

PartyA::PartyA(int input, int k, int l, osuCrypto::Channel sChl, osuCrypto::Channel cChl, CircuitInterface* cI) {
  x = input;
  kappa = k;
  lambda = l;
  serverChl = sChl;
  clientChl = cChl;
  circuit = cI;
}

PartyA::~PartyA() {}

/*
  Starts the protocol
*/
void PartyA::startProtocol() {
  //Generating random seeds and witnesses
  vector<CryptoPP::byte*> seedsA;
  vector<CryptoPP::byte*> witnesses;
  for(int j=0; j<lambda; j++) {
    seedsA.push_back(Util::randomByte(kappa));
    witnesses.push_back(Util::randomByte(kappa));
  }

  //Get the commitments of the seeds from party B
  vector<osuCrypto::block> commitmentsB;
  serverChl.recv(commitmentsB);
  cout << "A: has received commitments from other party" << endl;

  //First OT
  osuCrypto::KosOtExtSender sender;
  otSeedsWitnesses(&sender, serverChl, seedsA, witnesses, kappa);
  cout << "A: has done first OT" << endl;

  //Garbling
  pair<vector<CircuitInterface*>, vector<array<osuCrypto::block, 2>>> garblingInfo = garbling(circuit, seedsA);
  vector<CircuitInterface*> circuits = garblingInfo.first;
  vector<array<osuCrypto::block, 2>> otData = garblingInfo.second;

  //Second OT
  osuCrypto::PRNG prng(osuCrypto::sysRandomSeed()); //TODO: use own seed
  sender.sendChosen(otData, prng, serverChl);
  cout << "A: has done second OT" << endl;

  //Commitments
  vector<osuCrypto::block> commitmentsEncsInputsA;
  for(int j=0; j<lambda; j++) {
    for(int i=0; i<GV::n1; i++) {
      int r0 = Util::randomInt(0, numeric_limits<int>::max(), seedsA.at(j), iv); iv++;
      int r1 = Util::randomInt(0, numeric_limits<int>::max(), seedsA.at(j), iv); iv++;
      CryptoPP::byte *c0 = Util::commit(encs[j].at(i).at(0), r0);
      CryptoPP::byte *c1 = Util::commit(encs[j].at(i).at(1), r1);

      //Random order so that party B cannot extract my input when I give him decommitments
      if(Util::randomInt(0, 1) == 0) {
        commitmentsEncsInputsA.push_back(Util::byteToBlock(c0, 24));
        commitmentsEncsInputsA.push_back(Util::byteToBlock(c1, 24));
      } else {
        commitmentsEncsInputsA.push_back(Util::byteToBlock(c1, 24));
        commitmentsEncsInputsA.push_back(Util::byteToBlock(c0, 24));
      }
    }
  }

  vector<CryptoPP::block> commitmentsA;
  for(int j=0; j<lambda; j++) {
    int r = Util::randomInt(0, numeric_limits<int>::max(), seedsA.at(j), iv); iv++;
    GarbledCircuit *F = circuits.at(j)->exportCircuit();
    //pair<int, >CryptoPP::byte *b = F->toByte();
    //CryptoPP::byte *c = Util::commit(b , r);
  }

  clientChl.asyncSend(move(commitmentsEncsInputsA));
  cout << "A: has send commitments" << endl;

  //Receive gamma, seeds and witness
  vector<osuCrypto::block> gammaSeedsWitnessBlock;
  serverChl.recv(gammaSeedsWitnessBlock);
  cout << "A: has received gamma, seeds and witness" << endl;
  int gamma = Util::byteToInt(Util::blockToByte(gammaSeedsWitnessBlock.at(0), 4));

  //Checks the seeds and witness
  if(!checkSeedsWitness(gammaSeedsWitnessBlock, seedsA, witnesses)) {throw "Error!";}

  //Send garbled circuit, encoding inputs, commitments and decommitments to other party
  //TODO: commitments and decommitments
  CircuitInterface *circuit = circuits.at(gamma);
  GarbledCircuit *F = circuit->exportCircuit();

  vector<osuCrypto::block> encsInputsA;
  vector<vector<CryptoPP::byte*>> circuitEncs = encs[gamma];
  string xBitString = Util::intToBitString(x, GV::n1);
  for(int j=0; j<GV::n1; j++) {
    int b = (int) xBitString[j] - 48;
    encsInputsA.push_back(Util::byteToBlock(circuitEncs.at(j).at(b), kappa));
  }

  clientChl.asyncSend(move(F));
  cout << "A: has send F" << endl;
  clientChl.asyncSend(move(encsInputsA));
  cout << "A: has send my encoded inputs" << endl;
}

/*
  Garbling the circuits and prepare the ot data
*/
pair<vector<CircuitInterface*>, vector<array<osuCrypto::block, 2>>> PartyA::garbling(CircuitInterface* circuit, vector<CryptoPP::byte*> seedsA) {
  vector<CircuitInterface*> circuits;
  vector<array<osuCrypto::block, 2>> otData(lambda*GV::n2);

  for(int j=0; j<lambda; j++) {
    CircuitInterface *G = circuit->createInstance(kappa, seedsA.at(j));
    CircuitReader cr = CircuitReader();
    pair<bool, vector<vector<CryptoPP::byte*>>> import = cr.import(G, GV::filename);
    outputEncs[j] = cr.getOutputEnc();

    if(!import.first) {
      string msg = "Error! Could not import circuit";
      cout << msg << endl;
      throw msg;
    }

    circuits.push_back(G);
    encs[j] = import.second;

    for(int i=0; i<GV::n2; i++) {
      int index = i+(j*GV::n2);
      vector<CryptoPP::byte*> encsB = encs[j].at(GV::n1+i);
      osuCrypto::block block0 = Util::byteToBlock(encsB.at(0), kappa);
      osuCrypto::block block1 = Util::byteToBlock(encsB.at(1), kappa);
      otData[index] = {block0, block1};
    }
  }

  pair<vector<CircuitInterface*>, vector<array<osuCrypto::block, 2>>> output;
  output.first = circuits;
  output.second = otData;
  return output;
}

/*
  First OT-interaction. Sends seedsA and witnesses
*/
void PartyA::otSeedsWitnesses(osuCrypto::KosOtExtSender* sender, osuCrypto::Channel serverChl, vector<CryptoPP::byte*> seedsA, vector<CryptoPP::byte*> witnesses, int length) {
  vector<array<osuCrypto::block, 2>> otData(lambda);
  for(int j=0; j<lambda; j++) {
    osuCrypto::block block0 = Util::byteToBlock(seedsA.at(j), kappa);
    osuCrypto::block block1 = Util::byteToBlock(witnesses.at(j), kappa);
    otData[j] = {block0, block1};
  }
  osuCrypto::PRNG prng(osuCrypto::sysRandomSeed()); //TODO: use own seed
  sender->sendChosen(otData, prng, serverChl);
}

/*
  Checks that party A has correct seeds and witness
*/
bool PartyA::checkSeedsWitness(vector<osuCrypto::block> gammaSeedsWitnessBlock, vector<CryptoPP::byte*> seedsA, vector<CryptoPP::byte*> witnesses) {
  int gamma = Util::byteToInt(Util::blockToByte(gammaSeedsWitnessBlock.at(0), 4));

  for(int j=0; j<lambda; j++) {
    CryptoPP::byte *b = Util::blockToByte(gammaSeedsWitnessBlock.at(j+1), kappa);
    if(lambda == j) {
      if(memcmp(witnesses.at(j), b, kappa) != 0) {
        cout << "Error! Witness is not correct" << endl;
        return false;
      }
    } else if(memcmp(seedsA.at(j), b, kappa) != 0 && j!=gamma) {
      cout << "Error! Seed is not correct" << endl;
      return false;
    }
  }
  return true;
}
