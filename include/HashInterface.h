#ifndef HASHINTERFACE_H
#define HASHINTERFACE_H
#include "cryptlib.h"
#include "string"
using namespace std;

class HashInterface {
  public:
    HashInterface();
    virtual ~HashInterface();
    virtual void hashByte(CryptoPP::byte* plain, int plainLength, CryptoPP::byte *outputByte, int outputLength) = 0;
    virtual string toString() = 0;

  protected:

  private:
};

#endif // HASHINTERFACE_H
