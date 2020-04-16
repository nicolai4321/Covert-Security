#ifndef UTIL_H
#define UTIL_H
#include "aes.h"
#include "bitset"
#include "cryptlib.h"
#include "cryptoTools/Crypto/Commit.h"
#include "filters.h"
#include "hex.h"
#include "integer.h"
#include "iomanip"
#include "iostream"
#include "modes.h"
#include "osrng.h"
#include "randpool.h"
#include "string"
using namespace std;
using namespace std::chrono;

class Util {
  public:
    Util();

    //Variables
    static const int IV_LENGTH = 16;

    //Functions
    static osuCrypto::Commit commit(osuCrypto::block b, osuCrypto::block r);
    static osuCrypto::Commit commit(vector<pair<CryptoPP::byte*,int>> bytes, osuCrypto::block r, int totalLength);

    static void shuffle(CryptoPP::OFB_Mode<CryptoPP::AES>::Encryption *prng, vector<CryptoPP::byte*> v, CryptoPP::byte* seed, int seedLength, unsigned int iv);
    static unsigned int randomByte(CryptoPP::OFB_Mode<CryptoPP::AES>::Encryption *prng, CryptoPP::byte *output, int length, CryptoPP::byte *seed, int seedLength, unsigned int iv);
    static long randomInt(CryptoPP::AutoSeededRandomPool *asrp, int minInt, int maxInt);
    static long randomInt(CryptoPP::OFB_Mode<CryptoPP::AES>::Encryption *prng, int minInt, int maxInt, CryptoPP::byte* seed, int length, unsigned int iv);

    static osuCrypto::block byteToBlock(CryptoPP::byte *b, int length);
    static void blockToByte(osuCrypto::block b, int length, CryptoPP::byte *output);
    static string byteToString(CryptoPP::byte *b, int byteSize);
    static string blockToString(osuCrypto::block b, int length);
    static int byteToInt(CryptoPP::byte *b);
    static long byteToLong(CryptoPP::byte *b);
    static void stringToByte(string s, CryptoPP::byte *output, int byteSize);
    static osuCrypto::block stringToBlock(string s, int length);
    static string byteToBitString(CryptoPP::byte *b, int length);

    static void xorBytes(CryptoPP::byte *b0, CryptoPP::byte *b1, CryptoPP::byte *output, int length);
    static void mergeBytes(CryptoPP::byte *b0, CryptoPP::byte *b1, int length, CryptoPP::byte *output);
    static int lsb(CryptoPP::byte *b, int length);

    static void printByte(CryptoPP::byte *b, int length);
    static void printByteInBits(CryptoPP::byte *b, int length);
    static void printBlockInBits(osuCrypto::block b, int length);

  protected:

  private:
};

#endif // UTIL_H
