#ifndef HASHINTERFACE_H
#define HASHINTERFACE_H
#include "cryptlib.h"
using namespace std;

class HashInterface {
  public:
    HashInterface();
    virtual ~HashInterface();
    virtual CryptoPP::byte* hashByte(CryptoPP::byte* plain, int length) = 0;

  protected:

  private:
};

#endif // HASHINTERFACE_H
