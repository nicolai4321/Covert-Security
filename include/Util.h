#ifndef UTIL_H
#define UTIL_H
#include <string>

#include "cryptlib.h"
#include "randpool.h"
#include "integer.h"
#include "osrng.h"

using namespace std;

class Util {
  public:
    Util();

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
