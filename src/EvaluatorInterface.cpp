#include "EvaluatorInterface.h"
using namespace std;

EvaluatorInterface::EvaluatorInterface() {}
EvaluatorInterface::~EvaluatorInterface() {}

void EvaluatorInterface::giveCircuit(GarbledCircuit* gC) {
  F = gC;
  gatesEvaluated[CircuitInterface::CONST_ZERO] = F->getConstants().first;
  gatesEvaluated[CircuitInterface::CONST_ONE] = F->getConstants().second;
}
