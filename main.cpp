#include <iostream>
#include <string>
#include "PartyA.h"
#include "PartyB.h"
#include "Util.h"
#include <iomanip>

#include "cryptlib.h"
#include "randpool.h"
#include "integer.h"
#include "osrng.h"
#include "modes.h"
#include "aes.h"
#include "filters.h"
#include "hex.h"

using namespace std;

int main() {
  //hash
  /*
  CryptoPP::byte cc[CryptoPP::SHA256::DIGESTSIZE];
  Util::h("lolol", cc);
  cout << "1: " << Util::byteToString(cc, CryptoPP::SHA256::DIGESTSIZE) << endl;
  */

  /*
  CryptoPP::byte b0[CryptoPP::SHA256::DIGESTSIZE];
  Util::h("lolol", b0);
  cout << "0: " << Util::byteToString(b0, CryptoPP::SHA256::DIGESTSIZE) << endl;
  */

  //enc
  /*
  vector<CryptoPP::byte*> keys = Util::generateKeys();

  string p = " dette er en stoerre saetning saa lad os se hvad der sker";
  string c = Util::encrypt(p, keys);
  string de = Util::decrypt(c, keys);

  Util::printl("-------");
  cout << p << endl;
  cout << de << endl;
  Util::printl("-------");
  */



  PartyA partyA = PartyA(5);
  PartyB partyB = PartyB(3);

  unsigned char b = Util::toByte(13);
  unsigned char a = Util::toByte(8);

  return 0;
}
