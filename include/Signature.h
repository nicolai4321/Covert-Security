#ifndef SIGNATURE_H
#define SIGNATURE_H
#include <string>
#include "dsa.h"
#include "osrng.h"
using namespace std;

class Signature {
  public:
    static CryptoPP::DSA::PrivateKey generateRandomPrivateKey(int siz) {
      CryptoPP::AutoSeededRandomPool asrp;
      CryptoPP::DSA::PrivateKey sk;
      sk.GenerateRandomWithKeySize(asrp, siz);
      return sk;
    }

    static CryptoPP::DSA::PublicKey generatePublicKey(CryptoPP::DSA::PrivateKey sk) {
      CryptoPP::AutoSeededRandomPool asrp;
      CryptoPP::DSA::PublicKey pk;
      pk.AssignFrom(sk);
      if (!sk.Validate(asrp, 3) || !pk.Validate(asrp, 3)) {
        throw runtime_error("DSA key generation failed");
      }
      return pk;
    }

    static string sign(CryptoPP::DSA::PrivateKey sk, string message) {
      CryptoPP::AutoSeededRandomPool asrp;
      string signature;
      CryptoPP::DSA::Signer signer(sk);
      CryptoPP::StringSource ss1(message, true,
        new CryptoPP::SignerFilter(asrp, signer,
          new CryptoPP::StringSink(signature)
        )
      );
      return signature;
    }

    static bool verify(CryptoPP::DSA::PublicKey pk, string signature, string message) {
      try {
        CryptoPP::DSA::Verifier verifier(pk);
        CryptoPP::StringSource ss2(message+signature, true,
          new CryptoPP::SignatureVerificationFilter(
              verifier, NULL, CryptoPP::SignatureVerificationFilter::THROW_EXCEPTION));
        return true;
      } catch(...) {
        return false;
      }
    }

  protected:

  private:
};
#endif // SIGNATURE_H
