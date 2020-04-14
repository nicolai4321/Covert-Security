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
    static const int XOR = 0;
    static const int AND = 1;
    static const int OR = 2;

    //Functions
    static osuCrypto::Commit commit(osuCrypto::block b, osuCrypto::block r);
    static osuCrypto::Commit commit(vector<pair<CryptoPP::byte*,int>> bytes, osuCrypto::block r, int totalLength);

    static void shuffle(vector<CryptoPP::byte*> v, CryptoPP::byte *seed, int length, unsigned int iv);
    static void randomByte(CryptoPP::byte *output, int length);
    static unsigned int randomByte(CryptoPP::byte *output, int length, CryptoPP::byte *seed, int seedLength, unsigned int iv);
    static long randomInt(int minInt, int maxInt);
    static long randomInt(int minInt, int maxInt, CryptoPP::byte *seed, int length, unsigned int iv);

    static osuCrypto::block byteToBlock(CryptoPP::byte *b, int length);
    static void blockToByte(osuCrypto::block b, int length, CryptoPP::byte *output);
    static string byteToString(CryptoPP::byte *b, int byteSize);
    static string blockToString(osuCrypto::block b, int length);
    static int byteToInt(CryptoPP::byte *b);
    static long byteToLong(CryptoPP::byte *b);
    static void stringToByte(string s, CryptoPP::byte *output, int byteSize);
    static osuCrypto::block stringToBlock(string s, int length);
    static string byteToBitString(CryptoPP::byte *b, int length);

    static void byteOp(CryptoPP::byte *b0, CryptoPP::byte *b1, CryptoPP::byte *output, int op, int length);
    static void mergeBytes(CryptoPP::byte *b0, CryptoPP::byte *b1, int length, CryptoPP::byte *output);
    static int lsb(CryptoPP::byte *b, int length);
    static void printByte(CryptoPP::byte *b, int length);
    static void printByteInBits(CryptoPP::byte *b, int length);
    static void printBlockInBits(osuCrypto::block b, int length);

  protected:

  private:
};

#endif // UTIL_H
