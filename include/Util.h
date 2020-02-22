#ifndef UTIL_H
#define UTIL_H
#include <string>

#include "cryptlib.h"
#include "randpool.h"
#include "integer.h"
#include "osrng.h"
#include "hex.h"

using namespace std;

class Util {
  public:
    Util();

    static CryptoPP::byte* randomByte(int length);
    static void printByte(CryptoPP::byte* b, int length);
    static CryptoPP::byte* mergeBytes(CryptoPP::byte* b0, CryptoPP::byte* b1, int length);

    static CryptoPP::byte* h(string m);
    static string byteToString(CryptoPP::byte* b, int byteSize);
    static CryptoPP::byte* stringToByte(string s, int byteSize);

    static CryptoPP::byte* generateIV();
    static string encrypt(string p, CryptoPP::byte* key, CryptoPP::byte* iv);
    static string decrypt(string c, CryptoPP::byte* key, CryptoPP::byte* iv);

    static string randomString(int length);
    static long randomInt(int minInt, int maxInt);
    static string toBitString(int i, int length);
    static void printl(string m);
    static void printl(int i);
    static void printl(char c);

  protected:

  private:
};

#endif // UTIL_H
