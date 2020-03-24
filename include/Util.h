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
    static CryptoPP::byte* commit(osuCrypto::block b, osuCrypto::block r);
    static CryptoPP::byte* commit(vector<CryptoPP::byte*> bytes, osuCrypto::block r, int length);

    static void shuffle(vector<CryptoPP::byte*> v, CryptoPP::byte* seed, unsigned int iv);
    static CryptoPP::byte* randomByte(int length);
    static CryptoPP::byte* randomByte(int length, CryptoPP::byte* seed, unsigned int iv);
    static long randomInt(int minInt, int maxInt);
    static long randomInt(int minInt, int maxInt, CryptoPP::byte* seed, unsigned int iv);
    static string randomString(int length);

    static osuCrypto::block byteToBlock(CryptoPP::byte* b, int length);
    static CryptoPP::byte* blockToByte(osuCrypto::block b, int length);
    static string intToBitString(int i, int length);
    static string byteToString(CryptoPP::byte* b, int byteSize);
    static string blockToString(osuCrypto::block b, int length);
    static int byteToInt(CryptoPP::byte* b);
    static long byteToLong(CryptoPP::byte* b);
    static CryptoPP::byte* intToByte(int i);
    static CryptoPP::byte* longToByte(long i);
    static CryptoPP::byte* stringToByte(string s, int byteSize);
    static osuCrypto::block stringToBlock(string s, int length);

    static CryptoPP::byte* byteOp(CryptoPP::byte* b0, CryptoPP::byte* b1, string op, int length);
    static CryptoPP::byte* mergeBytes(CryptoPP::byte* b0, CryptoPP::byte* b1, int length);
    static CryptoPP::byte* mergeBytes(vector<CryptoPP::byte*> bytes, int length);
    static int lsb(CryptoPP::byte* b, int length);
    static void printByte(CryptoPP::byte* b, int length);
    static void printByteInBits(CryptoPP::byte* b, int length);
    static void printBlockInBits(osuCrypto::block b, int length);

    //Variables
    static const int SEED_LENGTH = 16;
    static const int IV_LENGTH = 16;
    static const int COMMIT_LENGTH = 16;

  protected:

  private:
};

#endif // UTIL_H
