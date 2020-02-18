#ifndef UTIL_H
#define UTIL_H
#include <string>

class Util {
  public:
    Util();
    static std::string randomString();
    static unsigned char toByte(int i);
    static std::string toBitString(int i);
    static void printl(std::string m);
    static void printl(int i);
    static void printl(char c);

  protected:

  private:
};

#endif // UTIL_H
