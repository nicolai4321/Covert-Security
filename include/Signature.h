#ifndef SIGNATURE_H
#define SIGNATURE_H
#include "pssr.h"
#include "rsa.h"
#include "SignatureHolder.h"
#include "string"
using namespace std;

class Signature {
  public:

  static pair<CryptoPP::RSA::PrivateKey, CryptoPP::RSA::PublicKey> generateKeys(int keySize) {
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(rng, keySize);
    CryptoPP::RSA::PrivateKey sk(params);
    CryptoPP::RSA::PublicKey pk(params);
    pair<CryptoPP::RSA::PrivateKey, CryptoPP::RSA::PublicKey> output(sk, pk);
    return output;
  }

  static pair<CryptoPP::SecByteBlock, size_t> sign(CryptoPP::RSA::PrivateKey sk, CryptoPP::byte *msg, int msgLength) {
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::RSASS<CryptoPP::PSS, CryptoPP::SHA256>::Signer signer(sk);
    CryptoPP::SecByteBlock signature(signer.MaxSignatureLength());
    size_t signatureLength = signer.SignMessage(rng, msg, msgLength, signature);
    if(signatureLength > signer.MaxSignatureLength()) throw runtime_error("Error! Signature length exeeded");
    signature.resize(signatureLength);

    pair<CryptoPP::SecByteBlock, size_t> output(signature, signatureLength);
    return output;
  }

  static bool verify(CryptoPP::RSA::PublicKey pk, SignatureHolder *sh) {
    return verify(pk, sh->getMsg(), sh->getMsgLength(), sh->getSignature(), sh->getSignatureLength());
  }

  static bool verify(CryptoPP::RSA::PublicKey pk, CryptoPP::byte *msg, int msgLength, CryptoPP::SecByteBlock signature, size_t signatureLength) {
    CryptoPP::RSASS<CryptoPP::PSS, CryptoPP::SHA256>::Verifier verifier(pk);
    return verifier.VerifyMessage(msg, msgLength, signature, signatureLength);
  }

  protected:

  private:
};
#endif // SIGNATURE_H
