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
  vector<unsigned int> seedsA;
  vector<unsigned int> witnesses;
  for(int j=0; j<lambda; j++) {
    seedsA.push_back(Util::randomInt(0, (INT_MAX-1000000))); //TODO
    witnesses.push_back(Util::randomInt(0, INT_MAX));
  }

  //Get the commitments of the seeds from party B
  vector<CryptoPP::byte*> commitmentsB;
  serverChl.recv(commitmentsB);

  //First OT
  osuCrypto::KosOtExtSender sender;
  otSeedsWitnesses(&sender, serverChl, seedsA, witnesses);

  //Garbling
  pair<vector<CircuitInterface*>, vector<array<osuCrypto::block, 2>>> garblingInfo = garbling(circuit, seedsA);
  vector<CircuitInterface*> circuits = garblingInfo.first;
  vector<array<osuCrypto::block, 2>> otData = garblingInfo.second;

  //Second OT
  osuCrypto::PRNG prng(osuCrypto::sysRandomSeed()); //TODO: use own seed
  sender.sendChosen(otData, prng, serverChl);

  //Commitments
  /*
  vector<pair<CryptoPP::byte*,CryptoPP::byte*>> commitmentsA;
  for(int j=0; j<lambda; j++) {
    for(int i=0; i<GV::n1; i++) {
      pair<CryptoPP::byte*, CryptoPP::byte*> p;
      p.first = Util::commit(encs[j].at(i).at(0), seedsA.at(j));
      p.second = Util::commit(encs[j].at(i).at(1), seedsA.at(j));
      commitmentsA.push_back(p);
    }
  }

  for(int j=0; j<lambda; j++) {
    vector<vector<CryptoPP::byte*>> outputEncodings = outputEncs[j];
    //outputEncodings
  }*/

  //Receive gamma, seeds and witness
  vector<unsigned int> gammaSeedsWitnessBlock;
  serverChl.recv(gammaSeedsWitnessBlock);
  unsigned int gamma = gammaSeedsWitnessBlock.at(0);

  //Checks the seeds and witness
  if(!checkSeedsWitness(gammaSeedsWitnessBlock, seedsA, witnesses)) {throw "Error!";}

  //Send garbled circuit, encoding inputs, commitments and decommitments to other party
  //TODO: commitments and decommitments
  CircuitInterface *circuit = circuits.at(gamma);
  GarbledCircuit *F = circuit->exportCircuit();

  vector<CryptoPP::byte*> encsInputsA;
  vector<vector<CryptoPP::byte*>> circuitEncs = encs[gamma];
  string xBitString = Util::toBitString(x, GV::n1);
  for(int j=0; j<GV::n1; j++) {
    int b = (int) xBitString[j] - 48;
    encsInputsA.push_back(circuitEncs.at(j).at(b));
  }

  clientChl.asyncSend(move(F));
  clientChl.asyncSend(move(encsInputsA));
}

/*
  Garbling the circuits and prepare the ot data
*/
pair<vector<CircuitInterface*>, vector<array<osuCrypto::block, 2>>> PartyA::garbling(CircuitInterface* circuit, vector<unsigned int> seedsA) {
  int blockIndexesRequired = ceil(((float) kappa)/((float) sizeof(long)));
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

      //An entry in a block can hold the size of long (8 bytes)
      osuCrypto::block block0;
      osuCrypto::block block1;

      for(int l=0; l<blockIndexesRequired; l++) {
        block0[l] = Util::byteToLong(encsB.at(0)+(l*sizeof(long)));
        block1[l] = Util::byteToLong(encsB.at(1)+(l*sizeof(long)));
      }

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
void PartyA::otSeedsWitnesses(osuCrypto::KosOtExtSender* sender, osuCrypto::Channel serverChl, vector<unsigned int> seedsA, vector<unsigned int> witnesses) {
  vector<array<osuCrypto::block, 2>> otData(lambda);
  for(int j=0; j<lambda; j++) {
    otData[j] = { osuCrypto::toBlock(seedsA.at(j)), osuCrypto::toBlock(witnesses.at(j)) };
  }

  osuCrypto::PRNG prng(osuCrypto::sysRandomSeed()); //TODO: use own seed
  sender->sendChosen(otData, prng, serverChl);
}

/*
  Checks that party A has correct seeds and witness
*/
bool PartyA::checkSeedsWitness(vector<unsigned int> block, vector<unsigned int> seedsA, vector<unsigned int> witnesses) {
  unsigned int gamma = block.at(0);

  for(int j=0; j<lambda; j++) {
    if(lambda == j) {
      if(witnesses.at(j) != block.at(j+1)) {
        cout << "Error! Witness is not correct" << endl;
        return false;
      }
    } else if(seedsA.at(j) != block.at(j+1) && j!=gamma) {
      cout << "Error! Seed is not correct" << endl;
      return false;
    }
  }
  return true;
}
