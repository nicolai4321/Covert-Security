#include "HashAES.h"
using namespace std;

CryptoPP::byte* HashAES::byteQueueToByte(CryptoPP::ByteQueue* byteQueue) {
  int length = byteQueue->CurrentSize();
  CryptoPP::byte *b = new CryptoPP::byte[length];
  for(int i=0; i<length; i++) {
    b[i] = (*byteQueue)[i];
  }
  return b;
}

/*
  Encrypts message p
*/
CryptoPP::ByteQueue HashAES::encrypt(CryptoPP::byte* plain, int plainLength, CryptoPP::SecByteBlock* key, int keyLength) {
  CryptoPP::ByteQueue cipherQueue;
  CryptoPP::ByteQueue plainQueue;
  plainQueue.Put(plain, plainLength);

  CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption enc;
  enc.SetKey(*key, keyLength);
  CryptoPP::StreamTransformationFilter f1(enc, new CryptoPP::Redirector(cipherQueue));
  plainQueue.CopyTo(f1);
  f1.MessageEnd();

  return cipherQueue;
}

/*
  Decrypts message c
*/
CryptoPP::byte* HashAES::decrypt(CryptoPP::ByteQueue cipherQueue, CryptoPP::byte* key, int keyLength) {
  CryptoPP::ByteQueue recoverQueue;
  CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption dec;
  dec.SetKey(key, keyLength);

  CryptoPP::StreamTransformationFilter f2(dec, new CryptoPP::Redirector(recoverQueue));
  cipherQueue.CopyTo(f2);
  f2.MessageEnd();

  return byteQueueToByte(&recoverQueue);
}

/*
  The sigma function
*/
CryptoPP::byte *HashAES::sigmaFunc(CryptoPP::byte* b, int length) {
  __m128i block = _mm_load_si128((__m128i*) b);
  __m128i b0 = _mm_shuffle_epi32(block, 78);
  __m128i b1 = _mm_and_si128(block, _mm_set_epi64x(0xFFFFFFFFFFFFFFFF, 0x00));
  __m128i xored = _mm_xor_si128(b0, b1);
  CryptoPP::byte *output = new CryptoPP::byte[length];
  _mm_storeu_si128((__m128i*) output, xored);
  return output;
}

/*
  Hashing the byte with the AES-method
*/
CryptoPP::byte* HashAES::hashByte(CryptoPP::byte* plain, int length) {
  CryptoPP::byte *sigmaValue = sigmaFunc(plain, length);
  CryptoPP::ByteQueue cipherQueue = encrypt(sigmaValue, length, key, keyLength);
  CryptoPP::byte* cipher = byteQueueToByte(&cipherQueue);

  //cipher text is twice the size of sigmaValue
  CryptoPP::byte* cipher0 = new CryptoPP::byte[length];
  CryptoPP::byte* cipher1 = new CryptoPP::byte[length];
  memcpy(cipher0, cipher, length);
  memcpy(cipher1, cipher+length, length);
  cipher = Util::byteOp(cipher0, cipher1, "XOR", length);

  CryptoPP::byte *output = Util::byteOp(cipher, sigmaValue, "XOR", length);
  return output;
}

string HashAES::toString() {
  return "aes library";
}

HashAES::HashAES(CryptoPP::SecByteBlock* k, int kLength) {
  key = k;
  keyLength = kLength;
}

HashAES::~HashAES() {}
