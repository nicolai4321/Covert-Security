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

    static vector<CryptoPP::byte*> generateKeys();
    static string encrypt(string p, vector<CryptoPP::byte*> keys);
    static string decrypt(string c, vector<CryptoPP::byte*> keys);

    static string randomString(int length);
    static long randomInt(int minInt, int maxInt);
    static unsigned char toByte(int i);
    static string toBitString(int i);
    static void printl(string m);
    static void printl(int i);
    static void printl(char c);

  protected:

  private:
};

#endif // UTIL_H
