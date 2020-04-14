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

size_t SignatureHolder::getSignatureLength() {
  return signatureLength;
}

SignatureHolder::SignatureHolder(CryptoPP::byte *m, int mLength, CryptoPP::SecByteBlock s, size_t sLength) {
  msg = m;
  msgLength = mLength;
  signature = s;
  signatureLength = sLength;
}

SignatureHolder::~SignatureHolder() {
  delete msg;
}
