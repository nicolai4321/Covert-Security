#ifndef SIGNATUREHOLDER_H
#define SIGNATUREHOLDER_H
#include "cryptlib.h"
#include "secblock.h"
using namespace std;

class SignatureHolder {
  public:
    SignatureHolder(CryptoPP::byte *msg, int msgLength, CryptoPP::SecByteBlock signature, int signatureLength);
    virtual ~SignatureHolder();
    CryptoPP::byte *getMsg();
    CryptoPP::SecByteBlock getSignature();
    int getMsgLength();
    int getSignatureLength();

  protected:

  private:
    CryptoPP::byte *msg;
    int msgLength;
    CryptoPP::SecByteBlock signature;
    int signatureLength;
};

#endif // SIGNATUREHOLDER_H
