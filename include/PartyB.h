#ifndef PARTYB_H
#define PARTYB_H
#include <iostream>
#include "CircuitInterface.h"
#include "cryptlib.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Network/IOService.h"
#include "GV.h"
#include "libOTe/TwoChooseOne/KosOtExtReceiver.h"
#include "Util.h"
using namespace std;

class PartyB
{
  public:
    PartyB(int y, int kappa, int lambda, osuCrypto::Channel serverChl, osuCrypto::Channel clientChl);
    virtual ~PartyB();

  protected:

  private:
    int y;
    int kappa;
    int lambda;
    int gamma;
};

#endif // PARTYB_H
