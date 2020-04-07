#ifndef HASHNORMAL_H
#define HASHNORMAL_H
#include "HashInterface.h"
#include "ripemd.h"
#include "shake.h"
#include "string"
#include "Util.h"
using namespace std;

class HashNormal: public HashInterface {
  public:
    virtual CryptoPP::byte* hashByte(CryptoPP::byte* plain, int length);
    virtual string toString();
    HashNormal(int kappa);
    virtual ~HashNormal();

  protected:

  private:
    int kappa;
    CryptoPP::SHAKE128 hashFunc;
};

#endif // HASHNORMAL_H
