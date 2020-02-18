#include "Util.h"
#include <iostream>
#include <string>
#include <bitset>

#include "cryptlib.h"
#include "randpool.h"
#include "integer.h"
#include "osrng.h"

using namespace std;

Util::Util() {}

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

void Util::printl(string m) {
  cout << m << endl;
}

void Util::printl(int i) {
  cout << i << endl;
}

void Util::printl(char c) {
  cout << c << endl;
}
