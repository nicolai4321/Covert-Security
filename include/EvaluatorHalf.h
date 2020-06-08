#ifndef EVALUATORHALF_H
#define EVALUATORHALF_H
#include <iostream>
#include <map>
#include <string>
#include <vector>
#include "CircuitInterface.h"
#include "cryptlib.h"
#include "EvaluatorInterface.h"
#include "GV.h"
#include "HashInterface.h"
#include "Util.h"
using namespace std;

class EvaluatorHalf: public EvaluatorInterface {
  public:
    EvaluatorHalf(HashInterface *hashInterface);
    virtual ~EvaluatorHalf();
    virtual pair<bool, vector<CryptoPP::byte*>> evaluate(vector<CryptoPP::byte*> inputs);
    virtual pair<bool, vector<bool>> decode(vector<CryptoPP::byte*> encs);

  protected:

  private:
    HashInterface *h;
};

#endif // EVALUATORHALF_H
