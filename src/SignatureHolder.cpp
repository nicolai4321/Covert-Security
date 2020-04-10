#include "SignatureHolder.h"

CryptoPP::byte *SignatureHolder::getMsg() {
  return msg;
}

CryptoPP::SecByteBlock SignatureHolder::getSignature() {
  return signature;
}

int SignatureHolder::getMsgLength() {
 return msgLength;
}

int SignatureHolder::getSignatureLength() {
  return signatureLength;
}

SignatureHolder::SignatureHolder(CryptoPP::byte *m, int mLength, CryptoPP::SecByteBlock s, int sLength) {
  msg = m;
  msgLength = mLength;
  signature = s;
  signatureLength = sLength;
}

SignatureHolder::~SignatureHolder() {}
