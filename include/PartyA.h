#ifndef PARTYA_H
#define PARTYA_H
#include <iostream>
#include "CircuitInterface.h"
#include "CircuitReader.h"
#include "cryptlib.h"
#include "cryptoTools/Network/IOService.h"
#include "GV.h"
#include "libOTe/TwoChooseOne/KosOtExtSender.h"
using namespace std;

class PartyA
{
  public:
    PartyA(int x, int kappa, int lambda, osuCrypto::Channel serverChl, osuCrypto::Channel clientChl, CircuitInterface* F);
    virtual ~PartyA();

  protected:

  private:
};

#endif // PARTYA_H
