#ifndef HASHNORMAL_H
#define HASHNORMAL_H
#include "HashInterface.h"
#include "sha.h"
#include "string"
#include "Util.h"
using namespace std;

class HashNormal: public HashInterface {
  public:
    virtual CryptoPP::byte* hashByte(CryptoPP::byte *plain, int length);
    virtual string toString();
    HashNormal(int kappa);
    virtual ~HashNormal();

  protected:

  private:
    int kappa;
    CryptoPP::SHA256 hashFunc;
};

#endif // HASHNORMAL_H
