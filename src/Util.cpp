#include "Util.h"
#include <iostream>
#include <string>
#include <bitset>

Util::Util() {
}

/*
  returns a random string
*/
std::string Util::randomString() {
		std::string lettersLower = "abcdefghijklmnopqrstuvwxyz";
		std::string lettersUpper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
		std::string numbers = "0123456789";
		std::string combine = lettersLower+lettersUpper+numbers;

		//random
		return "needImplementation";
}

/*
 char contains 8 bits
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
  transform integer to a bit string
*/
std::string Util::toBitString(int i) {
  std::string s = std::bitset<64>(i).to_string();

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

void Util::printl(std::string m) {
  std::cout << m << std::endl;
}

void Util::printl(int i) {
  std::cout << i << std::endl;
}

void Util::printl(char c) {
  std::cout << c << std::endl;
}
