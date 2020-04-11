#ifndef SIGNATUREHOLDER_H
#define SIGNATUREHOLDER_H
#include "cryptlib.h"
#include "secblock.h"
using namespace std;

class SignatureHolder {
  public:
    SignatureHolder(CryptoPP::byte *msg, int msgLength, CryptoPP::SecByteBlock signature, size_t signatureLength);
    virtual ~SignatureHolder();
    CryptoPP::byte *getMsg();
    CryptoPP::SecByteBlock getSignature();
    int getMsgLength();
    size_t getSignatureLength();

  protected:

  private:
    CryptoPP::byte *msg;
    int msgLength;
    CryptoPP::SecByteBlock signature;
    size_t signatureLength;
};

#endif // SIGNATUREHOLDER_H
