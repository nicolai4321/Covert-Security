#include "Judge.h"
using namespace std;

bool Judge::accuse(int j, string signature, CryptoPP::byte* seedB, osuCrypto::block decommitB, osuCrypto::block commitA, vector<osuCrypto::block> commitEncsA,
                   vector<pair<int, unsigned char*>> transcriptSent1,
                   vector<pair<int, unsigned char*>> transcriptRecv1,
                   vector<pair<int, unsigned char*>> transcriptSent2,
                   vector<pair<int, unsigned char*>> transcriptRecv2) {
  CryptoPP::byte *commit = Util::commit(Util::byteToBlock(seedB, kappa), decommitB);
  osuCrypto::block commitB = Util::byteToBlock(commit, Util::COMMIT_LENGTH);

  string signatureMsg = PartyA::constructSignatureString(j, kappa, commitA, commitB, commitEncsA, transcriptSent1,
                                                         transcriptRecv1, transcriptSent2, transcriptRecv2);
  bool correctSignature = Signature::verify(pk, signature, signatureMsg);
  if(!correctSignature) return false;

  return true;
}

Judge::Judge(int k, CryptoPP::DSA::PublicKey publicKey){
  kappa = k;
  pk = publicKey;
}

Judge::~Judge(){
}
