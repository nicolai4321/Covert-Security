#ifndef HASHAES_H
#define HASHAES_H
#include "cryptlib.h"
#include "emmintrin.h"
#include "HashInterface.h"
#include "string"
#include "Util.h"
using namespace std;

class HashAES: public HashInterface {
  public:
    virtual CryptoPP::byte *hashByte(CryptoPP::byte *plain, int length);
    virtual string toString();
    HashAES(CryptoPP::SecByteBlock *key, int keyLength);
    virtual ~HashAES();

  protected:

  private:
    CryptoPP::byte *byteQueueToByte(CryptoPP::ByteQueue *byteQueue);
    CryptoPP::ByteQueue encrypt(CryptoPP::byte *plain, int plainLength, CryptoPP::SecByteBlock *key, int keyLength);
    CryptoPP::byte *decrypt(CryptoPP::ByteQueue cipherQueue, CryptoPP::byte* key, int keyLength);
    CryptoPP::byte *sigmaFunc(CryptoPP::byte *b, int length);

    CryptoPP::SecByteBlock *key;
    int keyLength;
};

#endif // HASHAES_H
