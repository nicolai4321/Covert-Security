#include "Util.h"
#include <iostream>
#include <string>
#include <bitset>
#include <iomanip>

#include "modes.h"
#include "aes.h"
#include "filters.h"
#include "cryptlib.h"
#include "randpool.h"
#include "integer.h"
#include "osrng.h"

using namespace std;

Util::Util() {}

/*
  hash function
*/
void Util::h(string m, CryptoPP::byte* b) {
  CryptoPP::SHA256 hash;
  hash.CalculateDigest(b, (CryptoPP::byte*) m.c_str(), m.length());
}

/*
  byte to string
*/
string Util::byteToString(CryptoPP::byte* b, int byteSize) {
  string output;
  CryptoPP::HexEncoder encoder;
  encoder.Attach(new CryptoPP::StringSink(output));
  encoder.Put(b, byteSize);
  encoder.MessageEnd();
  return output;
}

/*
  Constructs key and iv
*/
vector<CryptoPP::byte*> Util::generateKeys() {
  CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH];
  memset(key, 0x00, CryptoPP::AES::DEFAULT_KEYLENGTH);
  memset(key, 4, CryptoPP::AES::DEFAULT_KEYLENGTH);
  //prng.GenerateBlock(key, sizeof(key));

  CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];
  memset(iv, 0x00, CryptoPP::AES::BLOCKSIZE);
  //prng.GenerateBlock(iv, sizeof(iv));

  vector<CryptoPP::byte*> keys;
  keys.push_back(key);
  keys.push_back(iv);
  return keys;
}

/*
  Encrypts message
*/
string Util::encrypt(string p, vector<CryptoPP::byte*> keys) {
  CryptoPP::byte* key = keys.at(0);
  CryptoPP::byte* iv = keys.at(1);

  std::string c;
  CryptoPP::AES::Encryption aesEnc(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
  CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEnc(aesEnc, iv);

  CryptoPP::StreamTransformationFilter stf(cbcEnc, new CryptoPP::StringSink(c));
  stf.Put(reinterpret_cast<const unsigned char*>(p.c_str()), p.length());
  stf.MessageEnd();

  return c;
}

/*
  Decrypts message
*/
string Util::decrypt(string c, vector<CryptoPP::byte*> keys) {
  CryptoPP::byte* key = keys.at(0);
  CryptoPP::byte* iv = keys.at(1);

  string s;
  CryptoPP::AES::Decryption aesDec(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
  CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDec(aesDec, iv);

  CryptoPP::StreamTransformationFilter stf(cbcDec, new CryptoPP::StringSink(s));
  stf.Put(reinterpret_cast<const unsigned char*>(c.c_str()), c.size());
  stf.MessageEnd();

  return s;
}

void Util::randomByte(CryptoPP::byte* b, int length) {
  CryptoPP::AutoSeededRandomPool asrp;
  asrp.GenerateBlock(b, length);
}

/*
  Returns a random string that can contain
  numbers, upper- and lower-case letters.
*/
string Util::randomString(int length) {
  string lettersLower = "abcdefghijklmnopqrstuvwxyz";
  string lettersUpper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  string numbers = "0123456789";
  string combine = lettersLower+lettersUpper+numbers;
  string s = "";
  for(int i=0; i<length; i++) {
    long l = Util::randomInt(0, combine.size());
    s += combine[l];
  }

  return s;
}

/*
  Returns random number between minInt and maxInt
*/
long Util::randomInt(int minInt, int maxInt) {
  CryptoPP::AutoSeededRandomPool asrp;
  CryptoPP::Integer r;

  if(minInt = 0) {
    r = CryptoPP::Integer(asrp, CryptoPP::Integer(), CryptoPP::Integer(maxInt));
  } else {
    r = CryptoPP::Integer(asrp, CryptoPP::Integer(minInt), CryptoPP::Integer(maxInt));
  }

  long l = r.ConvertToLong();
  return l;
}

/*
 Char contains 8 bits
 - signed char [-128; 127]
 - unsigned char [0; 255]
 unsigned char can therefore be used as a byte
 since c++ does not have a byte type

 bitwise operations:
  &: and
  ^: xor
  |: or
  ~: not
*/
unsigned char Util::toByte(int i) {
  unsigned char c = (unsigned char)i;
  return c;
}

/*
  Transform integer to a bit-string
*/
string Util::toBitString(int i) {
  string s = bitset<64>(i).to_string();

  int index = 0;
  while(index < s.size()) {
    if(s[index] != '0') {
      break;
    }
    index++;
  }
  s = s.substr(index, 64-index);

  return s;
}

void Util::printByte(CryptoPP::byte* b, int length) {
  string s;
	CryptoPP::StringSource(b, length, true,
		new CryptoPP::HexEncoder(
			new CryptoPP::StringSink(s)
		)
	);
  cout << "byte: " << s << endl;
}

void Util::mergeBytes(CryptoPP::byte* b, CryptoPP::byte* b0, CryptoPP::byte* b1, int length) {
  memcpy(b, b0, length);
  memcpy(b+length, b1, length);
}

void Util::printl(string m) {
  cout << m << endl;
}

void Util::printl(int i) {
  cout << i << endl;
}

void Util::printl(char c) {
  cout << c << endl;
}
