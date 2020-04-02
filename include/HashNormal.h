#ifndef HASHNORMAL_H
#define HASHNORMAL_H
#include "HashInterface.h"
#include "Util.h"
using namespace std;

class HashNormal: public HashInterface {
  public:
    virtual CryptoPP::byte* hashByte(CryptoPP::byte* plain, int length);
    HashNormal();
    virtual ~HashNormal();

  protected:

  private:
};

#endif // HASHNORMAL_H
