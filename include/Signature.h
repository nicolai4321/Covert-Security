#ifndef SIGNATURE_H
#define SIGNATURE_H
//#include "dsa.h"
//#include "osrng.h"
#include "esign.h"
#include "SignatureHolder.h"
#include "string"
#include "whrlpool.h"
using namespace std;

class Signature {
  public:
    static pair<CryptoPP::ESIGN<CryptoPP::Whirlpool>::PrivateKey,
                CryptoPP::ESIGN<CryptoPP::Whirlpool>::PublicKey> generateKeys(int siz) {
      CryptoPP::AutoSeededRandomPool rng;
      CryptoPP::InvertibleESIGNFunction parameters;
      parameters.GenerateRandomWithKeySize(rng, siz);

      CryptoPP::ESIGN<CryptoPP::Whirlpool>::PrivateKey sk(parameters);
      CryptoPP::ESIGN<CryptoPP::Whirlpool>::PublicKey pk(parameters);
      pair<CryptoPP::ESIGN<CryptoPP::Whirlpool>::PrivateKey, CryptoPP::ESIGN<CryptoPP::Whirlpool>::PublicKey> output;
      output.first = sk;
      output.second = pk;
      return output;
    }

    static pair<CryptoPP::byte*, int> sign(CryptoPP::ESIGN<CryptoPP::Whirlpool>::PrivateKey sk, CryptoPP::byte *msg, int length) {
      CryptoPP::AutoSeededRandomPool rng;
      CryptoPP::ESIGN<CryptoPP::Whirlpool>::Signer signer(sk);
      CryptoPP::byte *signature = new CryptoPP::byte[signer.MaxSignatureLength()];
      signer.SignMessage(rng, msg, length, signature);

      pair<CryptoPP::byte*, int> output;
      output.first = signature;
      output.second = signer.SignatureLength();
      return output;
    }

    static bool verify(CryptoPP::ESIGN<CryptoPP::Whirlpool>::PublicKey pk, SignatureHolder *sh) {
      return verify(pk, sh->getMsg(), sh->getMsgLength(), sh->getSignature(), sh->getSignatureLength());
    }

    static bool verify(CryptoPP::ESIGN<CryptoPP::Whirlpool>::PublicKey pk, CryptoPP::byte *msg, int msgLength, CryptoPP::byte *signature, int sigLength) {
      CryptoPP::ESIGN<CryptoPP::Whirlpool>::Verifier verifier(pk);
      return verifier.VerifyMessage(msg, msgLength, signature, sigLength);
    }

  protected:

  private:
};
#endif // SIGNATURE_H
