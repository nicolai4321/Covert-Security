#include <iostream>
#include <string>

#include "PartyA.h"
#include "PartyB.h"
#include "Util.h"

using namespace std;

int main() {
  PartyA partyA = PartyA(5);
  PartyB partyB = PartyB(3);

  //Gates: XOR,AND
  unsigned char b = Util::toByte(13);
  unsigned char a = Util::toByte(8);

  return 0;
}
