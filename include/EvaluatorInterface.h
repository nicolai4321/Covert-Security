#ifndef EVALUATORINTERFACE_H
#define EVALUATORINTERFACE_H
#include <string>
#include <vector>
#include "CircuitInterface.h"
#include "GarbledCircuit.h"
#include "cryptlib.h"
#include "Util.h"
using namespace std;

class EvaluatorInterface {
  public:
    EvaluatorInterface();
    virtual ~EvaluatorInterface();
    virtual pair<bool, vector<CryptoPP::byte*>> evaluate(vector<CryptoPP::byte*> inputs) = 0;
    virtual pair<bool, vector<bool>> decode(vector<CryptoPP::byte*> encs) = 0;
    void giveCircuit(GarbledCircuit* F);

  protected:
    GarbledCircuit *F;
    map<string, CryptoPP::byte*> gatesEvaluated;

  private:
};

#endif // EVALUATORINTERFACE_H
