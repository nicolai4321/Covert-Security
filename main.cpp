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

  //----------
  //   HASH
  //----------
  /*
  CryptoPP::byte* h0 = Util::h("lolol");
  CryptoPP::byte* h1 = Util::h("lolola");

  cout << "0: " << Util::byteToString(h0, CryptoPP::SHA256::DIGESTSIZE) << endl;
  cout << "1: " << Util::byteToString(h1, CryptoPP::SHA256::DIGESTSIZE) << endl;
  */

  //----------
  //ENCRYPTION
  //----------
  /*
  CryptoPP::byte *key = Util::randomByte(CryptoPP::AES::DEFAULT_KEYLENGTH);
  CryptoPP::byte *iv = Util::generateIV();
  string p = " dette er en stoerre saetning saa lad os se hvad der sker";
  string c = Util::encrypt(p, key, iv);
  string de = Util::decrypt(c, key, iv);

  Util::printl("-------");
  cout << p << endl;
  cout << de << endl;
  Util::printl("-------");
  */

  PartyA partyA = PartyA(5);
  PartyB partyB = PartyB(3);

  return 0;
}
