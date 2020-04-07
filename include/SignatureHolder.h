#ifndef SIGNATUREHOLDER_H
#define SIGNATUREHOLDER_H
#include "cryptlib.h"
using namespace std;

class SignatureHolder {
  public:
    SignatureHolder(CryptoPP::byte *msg, int msgLength, CryptoPP::byte *signature, int signatureLength);
    virtual ~SignatureHolder();
    CryptoPP::byte *getMsg();
    CryptoPP::byte *getSignature();
    int getMsgLength();
    int getSignatureLength();

  protected:

  private:
    CryptoPP::byte *msg;
    int msgLength;
    CryptoPP::byte *signature;
    int signatureLength;
};

#endif // SIGNATUREHOLDER_H
