#ifndef PARTYB_H
#define PARTYB_H
#include <iostream>
#include "cryptlib.h"
#include "CircuitInterface.h"
#include "Util.h"
using namespace std;

class PartyB
{
  public:
    PartyB(int y, int kappa, int lambda);
    virtual ~PartyB();

  protected:

  private:
    int y;
    int kappa;
    int lambda;
    int gamma;
};

#endif // PARTYB_H
