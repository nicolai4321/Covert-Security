#include "HashHardware.h"
using namespace std;

__m128i HashHardware::sigmaFunc(CryptoPP::byte *b, int length) {
  __m128i block = _mm_load_si128((__m128i*) b);
  __m128i b0 = _mm_shuffle_epi32(block, 78);
  __m128i b1 = _mm_and_si128(block, _mm_set_epi64x(0xFFFFFFFFFFFFFFFF, 0x00));
  __m128i out = _mm_xor_si128(b0, b1);
  return out;
}

__m128i HashHardware::keyExpansionAssist(__m128i a, __m128i b) {
  b = _mm_shuffle_epi32 (b, 0xff);
  __m128i tmp = _mm_slli_si128 (a, 0x4);
  a = _mm_xor_si128 (a, tmp);
  a = _mm_xor_si128 (a, tmp);
  a = _mm_xor_si128 (a, tmp);
  return _mm_xor_si128 (a, b);
}

void HashHardware::keyExpansion(const unsigned char *userkey, __m128i *keySchedule) {
  keySchedule[0] = _mm_loadu_si128((__m128i*) userkey);

  keySchedule[1] = keyExpansionAssist(keySchedule[0], _mm_aeskeygenassist_si128(keySchedule[0], 0x1));
  keySchedule[2] = keyExpansionAssist(keySchedule[1], _mm_aeskeygenassist_si128(keySchedule[1], 0x2));
  keySchedule[3] = keyExpansionAssist(keySchedule[2], _mm_aeskeygenassist_si128(keySchedule[2], 0x4));
  keySchedule[4] = keyExpansionAssist(keySchedule[3], _mm_aeskeygenassist_si128(keySchedule[3], 0x8));
  keySchedule[5] = keyExpansionAssist(keySchedule[4], _mm_aeskeygenassist_si128(keySchedule[4], 0x10));
  keySchedule[6] = keyExpansionAssist(keySchedule[5], _mm_aeskeygenassist_si128(keySchedule[5], 0x20));
  keySchedule[7] = keyExpansionAssist(keySchedule[6], _mm_aeskeygenassist_si128(keySchedule[6], 0x40));
  keySchedule[8] = keyExpansionAssist(keySchedule[7], _mm_aeskeygenassist_si128(keySchedule[7], 0x80));
  keySchedule[9] = keyExpansionAssist(keySchedule[8], _mm_aeskeygenassist_si128(keySchedule[8], 0x1b));
  keySchedule[10] = keyExpansionAssist(keySchedule[9], _mm_aeskeygenassist_si128(keySchedule[9], 0x36));

  keySchedule[11] = _mm_aesimc_si128(keySchedule[9]);
  keySchedule[12] = _mm_aesimc_si128(keySchedule[8]);
  keySchedule[13] = _mm_aesimc_si128(keySchedule[7]);
  keySchedule[14] = _mm_aesimc_si128(keySchedule[6]);
  keySchedule[15] = _mm_aesimc_si128(keySchedule[5]);
  keySchedule[16] = _mm_aesimc_si128(keySchedule[4]);
  keySchedule[17] = _mm_aesimc_si128(keySchedule[3]);
  keySchedule[18] = _mm_aesimc_si128(keySchedule[2]);
  keySchedule[19] = _mm_aesimc_si128(keySchedule[1]);
}

__m128i HashHardware::encrypt(__m128i *msg, __m128i *key, int nrRounds) {
  __m128i tmp = _mm_loadu_si128(msg);
  tmp = _mm_xor_si128 (tmp, key[0]);

  for(int j=1; j<nrRounds; j++) {
    tmp = _mm_aesenc_si128 (tmp, key[j]);
  }
  tmp = _mm_aesenclast_si128 (tmp, key[nrRounds]);
  return tmp;
}

__m128i HashHardware::decrypt(__m128i *cipher, __m128i *key, int nrRounds) {
  __m128i tmp = _mm_loadu_si128(cipher);
  tmp = _mm_xor_si128(tmp, key[nrRounds]);
  for(int j=1; j <nrRounds; j++) {
    tmp = _mm_aesdec_si128 (tmp, key[nrRounds+j]);
  }
  tmp = _mm_aesdeclast_si128 (tmp, key[0]);
  return tmp;
}

void HashHardware::hashByte(CryptoPP::byte *plain, int plainLength, CryptoPP::byte *outputByte, int outputLength) {
  __m128i sigmaValue = sigmaFunc(plain, plainLength);
  __m128i cipher = encrypt(&sigmaValue, keySchedule, 10);
  __m128i xored = _mm_xor_si128(cipher, sigmaValue);
  _mm_storeu_si128((__m128i*) outputByte, xored);
}

string HashHardware::toString() {
  return "aes hardware";
}

HashHardware::HashHardware(CryptoPP::byte *key, int keyLength) {
  keyExpansion(key, keySchedule);
}

HashHardware::~HashHardware() {}
