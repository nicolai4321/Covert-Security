#ifndef SIGNATUREHOLDER_H
#define SIGNATUREHOLDER_H
#include <string>
using namespace std;

class SignatureHolder {
  public:
    SignatureHolder(string msg, string signature);
    virtual ~SignatureHolder();
    string getMsg();
    string getSignature();

  protected:

  private:
    string msg;
    string signature;
};

#endif // SIGNATUREHOLDER_H
