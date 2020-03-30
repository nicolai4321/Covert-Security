#ifndef JUDGE_H
#define JUDGE_H
#include "cryptlib.h"
#include "cryptoTools/Crypto/Commit.h"
#include "cryptoTools/Network/Channel.h"
#include "libOTe/TwoChooseOne/KosOtExtReceiver.h"
#include "libOTe/TwoChooseOne/KosOtExtSender.h"
#include "PartyA.h"
#include "Signature.h"
#include "Util.h"
using namespace std;

class Judge {
  public:
    Judge(int kappa, CryptoPP::DSA::PublicKey pk, CircuitInterface* circuit);
    virtual ~Judge();

    /*
      This method will determine if the accusation is valid or not
    */
    bool accuse(int j, string signature, CryptoPP::byte* seedB, osuCrypto::block decommitB, osuCrypto::block commitA, vector<osuCrypto::block> commitEncsA,
                vector<pair<int, unsigned char*>> transcriptSent1,
                vector<pair<int, unsigned char*>> transcriptRecv1,
                vector<pair<int, unsigned char*>> transcriptSent2,
                vector<pair<int, unsigned char*>> transcriptRecv2);

  protected:

  private:
    int kappa;
    CryptoPP::DSA::PublicKey pk;
    CircuitInterface* circuit;
};

#endif // JUDGE_H
