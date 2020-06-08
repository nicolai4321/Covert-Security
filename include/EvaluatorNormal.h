#ifndef EVALUATORNORMAL_H
#define EVALUATORNORMAL_H
#include <iostream>
#include <string>
#include <vector>
#include "CircuitInterface.h"
#include "cryptlib.h"
#include "EvaluatorInterface.h"
#include "GV.h"
#include "HashInterface.h"
using namespace std;

class EvaluatorNormal: public EvaluatorInterface {
  public:
    EvaluatorNormal(HashInterface *hashInterface);
    virtual ~EvaluatorNormal();
    virtual pair<bool, vector<CryptoPP::byte*>> evaluate(vector<CryptoPP::byte*> inputs);
    virtual pair<bool, vector<bool>> decode(vector<CryptoPP::byte*> encs);

  protected:

  private:
    HashInterface *h;
    bool decodeGate(CryptoPP::byte *encL, CryptoPP::byte *encR, CryptoPP::byte *enc, CryptoPP::byte *output);
};

#endif // EVALUATORNORMAL_H
