#ifndef EVALUATORNORMAL_H
#define EVALUATORNORMAL_H
#include <iostream>
#include <string>
#include <vector>
#include "CircuitInterface.h"
#include "cryptlib.h"
#include "EvaluatorInterface.h"
#include "GV.h"
using namespace std;

class EvaluatorNormal: public EvaluatorInterface {
  public:
    EvaluatorNormal();
    virtual ~EvaluatorNormal();
    virtual pair<bool, vector<CryptoPP::byte*>> evaluate(vector<CryptoPP::byte*> inputs);

  protected:

  private:
    pair<bool, CryptoPP::byte*> decodeGate(CryptoPP::byte* encL, CryptoPP::byte* encR, CryptoPP::byte* enc);
};

#endif // EVALUATORNORMAL_H
