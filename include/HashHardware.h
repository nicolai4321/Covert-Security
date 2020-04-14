#ifndef HASHHARDWARE_H
#define HASHHARDWARE_H
#include "cryptlib.h"
#include "emmintrin.h"
#include "HashInterface.h"
#include "smmintrin.h"
#include "stdint.h"
#include "stdio.h"
#include "string"
#include "Util.h"
#include "wmmintrin.h"
#include "x86intrin.h"
using namespace std;

/*
  Hashing with AES ECB-mode for a keysize of 128 bits/16 bytes and 10 rounds
*/
class HashHardware: public HashInterface {
  public:
    virtual void hashByte(CryptoPP::byte *plain, int plainLength, CryptoPP::byte *outputByte, int outputLength);
    virtual string toString();
    HashHardware(CryptoPP::byte *key, int keyLength);
    virtual ~HashHardware();

  protected:

  private:
    __m128i keySchedule[20];

    __m128i sigmaFunc(CryptoPP::byte *b, int length);
    inline __m128i keyExpansionAssist(__m128i a, __m128i b);
    void keyExpansion(const unsigned char *userkey, __m128i *keySchedule);
    __m128i encrypt(__m128i *msg, __m128i *key, int nrRounds);
    __m128i decrypt(__m128i *cipher, __m128i *key, int nrRounds);
};

#endif // HASHHARDWARE_H
