#ifndef HASHAES_H
#define HASHAES_H
#include "cryptlib.h"
#include "HashInterface.h"
#include "Util.h"
using namespace std;

class HashAES: public HashInterface {
  public:
    virtual CryptoPP::byte* hashByte(CryptoPP::byte* plain, int length);
    HashAES(CryptoPP::SecByteBlock* key, int keyLength);
    virtual ~HashAES();

  protected:

  private:
    CryptoPP::byte *sigmaFunc(CryptoPP::byte* b, int length);

    CryptoPP::SecByteBlock *key;
    int keyLength;
};

#endif // HASHAES_H
