#include "Util.h"
using namespace std;

Util::Util() {}

/*
  Returns the least significant bit
*/
int Util::lsb(CryptoPP::byte* b, int length) {
  string s = intToBitString(b[length-1], 1);
  return stoi(s);
}

/*
  bitwise operations:
  &: and
  ^: xor
  |: or
  ~: not
*/
CryptoPP::byte* Util::byteOp(CryptoPP::byte* b0, CryptoPP::byte* b1, string op, int length) {
  CryptoPP::byte *b = new CryptoPP::byte[length];
  for(int i=0; i<length; i++) {
    if(op.compare("XOR") == 0) {
      b[i] = b0[i] ^ b1[i];
    } else if(op.compare("AND") == 0) {
      b[i] = b0[i] & b1[i];
    } else if(op.compare("OR") == 0) {
      b[i] = b0[i] | b1[i];
    } else {
      cout << "Error! Unkown operator: '" << op << "'" << endl;
    }
  }
  return b;
}

/*
  Returns a hashed byte
*/
CryptoPP::byte* Util::h(CryptoPP::byte* b, int length) {
  string s = Util::byteToString(b, length);
  return h(s);
}

/*
  Returns a hashed byte
*/
CryptoPP::byte* Util::h(string m) {
  CryptoPP::byte* b = new CryptoPP::byte[CryptoPP::SHA256::DIGESTSIZE];
  CryptoPP::SHA256 hash;
  hash.CalculateDigest(b, (CryptoPP::byte*) m.c_str(), m.length());
  return b;
}

/*
  Commit
*/
CryptoPP::byte* Util::commit(CryptoPP::byte* b, int r) {
  osuCrypto::Commit *c = new osuCrypto::Commit(b, r % 55104); //TODO: longer commit, length?
  CryptoPP::byte *ptr = c->data();
  return ptr;
}

/*
  Constructs the initialization vector
*/
CryptoPP::byte* Util::generateIV() {
  CryptoPP::AutoSeededRandomPool asrp;
  CryptoPP::byte *iv = new CryptoPP::byte[CryptoPP::AES::BLOCKSIZE];
  asrp.GenerateBlock(iv, CryptoPP::AES::BLOCKSIZE);

  return iv;
}

/*
  Encrypts message p
*/
string Util::encrypt(string p, CryptoPP::byte* key, CryptoPP::byte* iv) {
  CryptoPP::AES::Encryption aesEnc(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
  CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEnc(aesEnc, iv);

  std::string c;
  CryptoPP::StreamTransformationFilter stf(cbcEnc, new CryptoPP::StringSink(c));
  stf.Put(reinterpret_cast<const unsigned char*>(p.c_str()), p.length());
  stf.MessageEnd();

  return c;
}

/*
  Decrypts message c
*/
string Util::decrypt(string c, CryptoPP::byte* key, CryptoPP::byte* iv) {
  CryptoPP::AES::Decryption aesDec(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
  CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDec(aesDec, iv);

  string s;
  CryptoPP::StreamTransformationFilter stf(cbcDec, new CryptoPP::StringSink(s));
  stf.Put(reinterpret_cast<const unsigned char*>(c.c_str()), c.size());
  stf.MessageEnd();

  return s;
}

/*
  Returns a random byte
*/
CryptoPP::byte* Util::randomByte(int length) {
  CryptoPP::AutoSeededRandomPool asrp;
  CryptoPP::byte* b = new CryptoPP::byte[length];
  asrp.GenerateBlock(b, length);
  return b;
}

/*
  Returns a random byte with a seed
*/
CryptoPP::byte* Util::randomByte(int length, CryptoPP::byte* seed, unsigned int iv) {
  CryptoPP::OFB_Mode<CryptoPP::AES>::Encryption prng;
  prng.SetKeyWithIV(seed, SEED_LENGTH_BITS, intToByte(iv), IV_LENGTH_BITS);

  CryptoPP::byte *b = new CryptoPP::byte[length];
  prng.GenerateBlock(b, length);
  return b;
}

/*
  Returns random number between minInt and maxInt
*/
long Util::randomInt(int minInt, int maxInt) {
  CryptoPP::AutoSeededRandomPool asrp;
  CryptoPP::Integer r;

  if(minInt == 0) {
    r = CryptoPP::Integer(asrp, CryptoPP::Integer(), CryptoPP::Integer(maxInt));
  } else {
    r = CryptoPP::Integer(asrp, CryptoPP::Integer(minInt), CryptoPP::Integer(maxInt));
  }

  long l = r.ConvertToLong();
  return l;
}

/*
  Returns random number between minInt and maxInt with seed
*/
long Util::randomInt(int minInt, int maxInt, CryptoPP::byte* seed, unsigned int iv) {
  CryptoPP::OFB_Mode<CryptoPP::AES>::Encryption prng;
  prng.SetKeyWithIV(seed, SEED_LENGTH_BITS, intToByte(iv), IV_LENGTH_BITS);

  CryptoPP::Integer r;
  if(minInt == 0) {
    r = CryptoPP::Integer(prng, CryptoPP::Integer(), CryptoPP::Integer(maxInt));
  } else {
    r = CryptoPP::Integer(prng, CryptoPP::Integer(minInt), CryptoPP::Integer(maxInt));
  }
  long l = r.ConvertToLong();
  return l;
}

/*
  Returns a random string that can contain
  numbers, upper- and lower-case letters.
  Returns a random byte with a seed
*/
string Util::randomString(int length) {
  string lettersLower = "abcdefghijklmnopqrstuvwxyz";
  string lettersUpper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  string numbers = "0123456789";
  string combine = lettersLower+lettersUpper+numbers;
  string s = "";
  for(int i=0; i<length; i++) {
    long l = Util::randomInt(0, combine.size());
    s += combine[l];
  }

  return s;
}

/*
  Transform integer to a bit-string
*/
string Util::intToBitString(int i, int length) {
  string s = bitset<256>(i).to_string();
  s = s.substr(256-length, length);
  return s;
}

/*
  Transform integer to byte (32 bits)
*/
CryptoPP::byte* Util::intToByte(int i) {
  CryptoPP::byte *b = new CryptoPP::byte[sizeof(int)];
  memcpy(b, &i, sizeof i);
  return b;
}

/*
  Transform byte to integer (32 bits)
*/
int Util::byteToInt(CryptoPP::byte* b) {
  int i;
  memcpy(&i, b, sizeof i);
  return i;
}

/*
  Transform integer to byte (64 bits)
*/
CryptoPP::byte* Util::longToByte(long i) {
  CryptoPP::byte *b = new CryptoPP::byte[sizeof(long)];
  memcpy(b, &i, sizeof(long));
  return b;
}

/*
  Transform byte to integer (64 bits)
*/
long Util::byteToLong(CryptoPP::byte* b) {
  long i;
  memcpy(&i, b, sizeof(long));
  return i;
}

/*
  Merges two bytes to one
*/
CryptoPP::byte* Util::mergeBytes(CryptoPP::byte* b0, CryptoPP::byte* b1, int length) {
  CryptoPP::byte* b = new CryptoPP::byte[2*length];
  memcpy(b, b0, length);
  memcpy(b+length, b1, length);
  return b;
}

/*
  Transforms a byte to a string
*/
string Util::byteToString(CryptoPP::byte* b, int byteSize) {
  string output;
  CryptoPP::HexEncoder encoder;
  encoder.Attach(new CryptoPP::StringSink(output));
  encoder.Put(b, byteSize);
  encoder.MessageEnd();
  return output;
}

/*
  Transform a string to a byte
*/
CryptoPP::byte* Util::stringToByte(string s, int length) {
  string sink;
  CryptoPP::StringSource ss(s, true,
    new CryptoPP::HexDecoder(
        new CryptoPP::StringSink(sink)
    )
  );
  CryptoPP::byte *b = (CryptoPP::byte*) sink.data();

  //TODO find a better method
  CryptoPP::byte *output = new CryptoPP::byte[length];
  for(int i=0; i<length; i++) {
    output[i] = b[i];
  }

  return output;
}

/*
  Prints a byte in string form
*/
void Util::printByte(CryptoPP::byte* b, int length) {
  string s;
	CryptoPP::StringSource(b, length, true,
		new CryptoPP::HexEncoder(
			new CryptoPP::StringSink(s)
		)
	);
  cout << "byte: " << s << endl;
}

void Util::printByteInBits(CryptoPP::byte* b, int length) {
  cout << "bits: ";
  for(int i=(length-1); i>=0; i--) {
    cout << intToBitString((int) b[i],8) << " ";
  }
  cout << endl;
}
