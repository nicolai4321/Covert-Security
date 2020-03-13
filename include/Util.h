#ifndef UTIL_H
#define UTIL_H
#include <bitset>
#include <iomanip>
#include <iostream>
#include <string>

#include "aes.h"
#include "cryptlib.h"
#include "cryptoTools/Crypto/Commit.h"
#include "filters.h"
#include "hex.h"
#include "integer.h"
#include "modes.h"
#include "osrng.h"
#include "randpool.h"
using namespace std;

class Util {
  public:
    Util();

    //Functions
    static CryptoPP::byte* generateIV();
    static string encrypt(string p, CryptoPP::byte* key, CryptoPP::byte* iv);
    static string decrypt(string c, CryptoPP::byte* key, CryptoPP::byte* iv);
    static CryptoPP::byte* h(string m);
    static CryptoPP::byte* h(CryptoPP::byte* b, int length);
    static CryptoPP::byte* commit(CryptoPP::byte* b, int r);

    static CryptoPP::byte* randomByte(int length);
    static CryptoPP::byte* randomByte(int length, CryptoPP::byte* seed, unsigned int iv);
    static long randomInt(int minInt, int maxInt);
    static long randomInt(int minInt, int maxInt, CryptoPP::byte* seed, unsigned int iv);
    static string randomString(int length);

    static string intToBitString(int i, int length);
    static string byteToString(CryptoPP::byte* b, int byteSize);
    static int byteToInt(CryptoPP::byte* b);
    static long byteToLong(CryptoPP::byte* b);
    static CryptoPP::byte* intToByte(int i);
    static CryptoPP::byte* longToByte(long i);
    static CryptoPP::byte* stringToByte(string s, int byteSize);

    static CryptoPP::byte* byteOp(CryptoPP::byte* b0, CryptoPP::byte* b1, string op, int length);
    static CryptoPP::byte* mergeBytes(CryptoPP::byte* b0, CryptoPP::byte* b1, int length);
    static int lsb(CryptoPP::byte* b, int length);
    static void printByte(CryptoPP::byte* b, int length);
    static void printByteInBits(CryptoPP::byte* b, int length);

    //Variables
    static const int SEED_LENGTH = 32/8;

  protected:

  private:
    static const int SEED_LENGTH_BITS = 32;
    static const int IV_LENGTH_BITS = 16;
};

#endif // UTIL_H
