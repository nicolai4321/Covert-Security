#ifndef PARTYA_H
#define PARTYA_H
#include <iostream>
#include "cryptlib.h"
#include "CircuitInterface.h"
using namespace std;

class PartyA
{
  public:
    PartyA(int x, int kappa, CircuitInterface* F);
    virtual ~PartyA();

  protected:

  private:
};

#endif // PARTYA_H
