#include "SignatureHolder.h"

string SignatureHolder::getMsg() {
  return msg;
}

string SignatureHolder::getSignature() {
  return signature;
}

SignatureHolder::SignatureHolder(string m, string s) {
  msg = m;
  signature = s;
}

SignatureHolder::~SignatureHolder() {}
