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
  vector<CryptoPP::byte*> commitmentsB;
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
  vector<CryptoPP::byte*> commitmentsEncsInputsA;
  for(int j=0; j<lambda; j++) {
    for(int i=0; i<GV::n1; i++) {
      int r = Util::randomInt(0, numeric_limits<int>::max(), seedsA.at(j), j);
      CryptoPP::byte *c0 = Util::commit(encs[j].at(i).at(0), r);
      CryptoPP::byte *c1 = Util::commit(encs[j].at(i).at(1), r);

      //Random order so that party B cannot extract my input when I give him decommitments
      if(Util::randomInt(0, 1) == 0) {
        commitmentsEncsInputsA.push_back(c0);
        commitmentsEncsInputsA.push_back(c1);
      } else {
        commitmentsEncsInputsA.push_back(c1);
        commitmentsEncsInputsA.push_back(c0);
      }
    }
  }

  //for(int j=0; j<lambda; j++) {
  //  vector<vector<CryptoPP::byte*>> outputEncodings = outputEncs[j];
  //  //outputEncodings
  //}

  clientChl.asyncSend(move(commitmentsEncsInputsA));
  cout << "A: has send commitments" << endl;

  //Receive gamma, seeds and witness
  vector<CryptoPP::byte*> gammaSeedsWitnessBlock;
  serverChl.recv(gammaSeedsWitnessBlock);
  cout << "A: has received gamma, seeds and witness" << endl;
  int gamma = Util::byteToInt(gammaSeedsWitnessBlock.at(0));

  //Checks the seeds and witness
  if(!checkSeedsWitness(gammaSeedsWitnessBlock, seedsA, witnesses)) {throw "Error!";}

  //Send garbled circuit, encoding inputs, commitments and decommitments to other party
  //TODO: commitments and decommitments
  CircuitInterface *circuit = circuits.at(gamma);
  GarbledCircuit *F = circuit->exportCircuit();

  vector<CryptoPP::byte*> encsInputsA;
  vector<vector<CryptoPP::byte*>> circuitEncs = encs[gamma];
  string xBitString = Util::intToBitString(x, GV::n1);
  for(int j=0; j<GV::n1; j++) {
    int b = (int) xBitString[j] - 48;
    encsInputsA.push_back(circuitEncs.at(j).at(b));
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
  int blockIndexesRequired = ceil(((float) kappa)/((float) sizeof(long)));

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
void PartyA::otSeedsWitnesses(osuCrypto::KosOtExtSender* sender, osuCrypto::Channel serverChl, vector<CryptoPP::byte*> seedsA, vector<CryptoPP::byte*> witnesses, int length) {
  int blockIndexesRequired = ceil(((float) length)/((float) sizeof(long)));
  vector<array<osuCrypto::block, 2>> otData(lambda);
  for(int j=0; j<lambda; j++) {
    osuCrypto::block block0;
    osuCrypto::block block1;
    for(int l=0; l<blockIndexesRequired; l++) {
      block0[l] = Util::byteToLong(seedsA.at(j)+(l*sizeof(long)));
      block1[l] = Util::byteToLong(witnesses.at(j)+(l*sizeof(long)));
    }

    otData[j] = {block0, block1};
  }

  osuCrypto::PRNG prng(osuCrypto::sysRandomSeed()); //TODO: use own seed
  sender->sendChosen(otData, prng, serverChl);
}

/*
  Checks that party A has correct seeds and witness
*/
bool PartyA::checkSeedsWitness(vector<CryptoPP::byte*> gammaSeedsWitnessBlock, vector<CryptoPP::byte*> seedsA, vector<CryptoPP::byte*> witnesses) {
  int gamma = Util::byteToInt(gammaSeedsWitnessBlock.at(0));

  for(int j=0; j<lambda; j++) {
    if(lambda == j) {
      if(memcmp(witnesses.at(j), gammaSeedsWitnessBlock.at(j+1), kappa) != 0) {
        cout << "Error! Witness is not correct" << endl;
        return false;
      }
    } else if(memcmp(seedsA.at(j), gammaSeedsWitnessBlock.at(j+1), Util::SEED_LENGTH) != 0 && j!=gamma) {
      cout << "Error! Seed is not correct" << endl;
      return false;
    }
  }
  return true;
}
