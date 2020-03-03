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

    static CryptoPP::byte* generateIV();
    static string encrypt(string p, CryptoPP::byte* key, CryptoPP::byte* iv);
    static string decrypt(string c, CryptoPP::byte* key, CryptoPP::byte* iv);
    static CryptoPP::byte* h(string m);
    static CryptoPP::byte* h(CryptoPP::byte* b, int length);
    static CryptoPP::byte* commit(CryptoPP::byte* b, int r);

    static CryptoPP::byte* randomByte(int length);
    static CryptoPP::byte* randomByte(int length, unsigned int seed);
    static long randomInt(int minInt, int maxInt);
    static string randomString(int length);

    static string toBitString(int i, int length);
    static string byteToString(CryptoPP::byte* b, int byteSize);
    static CryptoPP::byte* intToByte(int i);
    static CryptoPP::byte* stringToByte(string s, int byteSize);

    static CryptoPP::byte* byteOp(CryptoPP::byte* b0, CryptoPP::byte* b1, string op, int length);
    static CryptoPP::byte* mergeBytes(CryptoPP::byte* b0, CryptoPP::byte* b1, int length);
    static int lsb(CryptoPP::byte* b, int length);
    static void printByte(CryptoPP::byte* b, int length);
    static void printByteInBits(CryptoPP::byte* b, int length);
    static void printl(string m);
    static void printl(int i);
    static void printl(char c);

  protected:

  private:
};

#endif // UTIL_H
