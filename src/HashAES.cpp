#include "HashAES.h"
using namespace std;

/*
  The sigma function
*/
CryptoPP::byte* HashAES::sigmaFunc(CryptoPP::byte* b, int length) {
  //split byte in left and right
  int halfLength = length/2;
  CryptoPP::byte* b0 = new CryptoPP::byte[halfLength];
  CryptoPP::byte* b1 = new CryptoPP::byte[halfLength];
  memcpy(b0, b+halfLength, halfLength);
  memcpy(b1, b, halfLength);

  //b0 xor b1 || b0
  CryptoPP::byte *xored = Util::byteOp(b0, b1, "XOR", halfLength);
  return Util::mergeBytes(b0, xored, halfLength);
}

/*
  Hashing the byte with the AES-method
*/
CryptoPP::byte* HashAES::hashByte(CryptoPP::byte* plain, int length) {
  CryptoPP::byte *sigmaValue = sigmaFunc(plain, length);
  CryptoPP::ByteQueue cipherQueue = Util::encrypt(plain, length, key, keyLength);
  CryptoPP::byte* cipher = Util::byteQueueToByte(&cipherQueue);

  //cipher text is twice the size of sigmaValue
  CryptoPP::byte* cipher0 = new CryptoPP::byte[length];
  CryptoPP::byte* cipher1 = new CryptoPP::byte[length];
  memcpy(cipher0, cipher, length);
  memcpy(cipher1, cipher+length, length);
  cipher = Util::byteOp(cipher0, cipher1, "XOR", length);

  CryptoPP::byte *output = Util::byteOp(cipher, sigmaValue, "XOR", length);
  return output;
}

HashAES::HashAES(CryptoPP::SecByteBlock* k, int kLength) {
  key = k;
  keyLength = kLength;
}

HashAES::~HashAES() {}
