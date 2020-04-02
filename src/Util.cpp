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
  Commit (16 bytes)
*/
CryptoPP::byte* Util::commit(osuCrypto::block b, osuCrypto::block r) {
  osuCrypto::Commit *c = new osuCrypto::Commit(b, r);
  CryptoPP::byte *ptr = c->data();
  return ptr;
}

/*
  Commit (16 bytes)
*/
CryptoPP::byte* Util::commit(vector<CryptoPP::byte*> bytes, osuCrypto::block r, int length) {
  int nrBytes = bytes.size();
  osuCrypto::u8 arr[nrBytes*length];

  for(int i=0; i<nrBytes; i++) {
    for(int j=0; j<length; j++) {
      arr[j+(i*length)] = bytes.at(i)[j];
    }
  }
  osuCrypto::span<osuCrypto::u8> s = {arr, nrBytes*length};
  osuCrypto::Commit *c = new osuCrypto::Commit(s, r);
  CryptoPP::byte *ptr = c->data();

  return ptr;
}

/*
  Encrypts message p
*/
CryptoPP::ByteQueue Util::encrypt(CryptoPP::byte* plain, int plainLength, CryptoPP::SecByteBlock* key, int keyLength) {
  CryptoPP::ByteQueue cipherQueue;
  CryptoPP::ByteQueue plainQueue;
  plainQueue.Put(plain, plainLength);

  CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption enc;
  enc.SetKey(*key, keyLength);
  CryptoPP::StreamTransformationFilter f1(enc, new CryptoPP::Redirector(cipherQueue));
  plainQueue.CopyTo(f1);
  f1.MessageEnd();

  return cipherQueue;
}

/*
  Decrypts message c
*/
CryptoPP::byte* Util::decrypt(CryptoPP::ByteQueue cipherQueue, CryptoPP::byte* key, int keyLength) {
  CryptoPP::ByteQueue recoverQueue;
  CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption dec;
  dec.SetKey(key, keyLength);

  CryptoPP::StreamTransformationFilter f2(dec, new CryptoPP::Redirector(recoverQueue));
  cipherQueue.CopyTo(f2);
  f2.MessageEnd();

  return byteQueueToByte(&recoverQueue);
}

CryptoPP::byte* Util::byteQueueToByte(CryptoPP::ByteQueue* byteQueue) {
  int length = byteQueue->CurrentSize();
  CryptoPP::byte *b = new CryptoPP::byte[length];
  for(int i=0; i<length; i++) {
    b[i] = (*byteQueue)[i];
  }
  return b;
}

/*
  Randomly shuffles a vector
*/
void Util::shuffle(vector<CryptoPP::byte*> v, CryptoPP::byte* seed, unsigned int iv) {
  CryptoPP::byte *ivByte = new CryptoPP::byte[IV_LENGTH];
  memset(ivByte, 0x00, IV_LENGTH);
  memcpy(ivByte, longToByte(iv), 8);
  CryptoPP::OFB_Mode<CryptoPP::AES>::Encryption prng;
  prng.SetKeyWithIV(seed, SEED_LENGTH, ivByte, IV_LENGTH);

  prng.Shuffle(v.begin(), v.end());
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
  CryptoPP::byte *ivByte = new CryptoPP::byte[IV_LENGTH];
  memset(ivByte, 0x00, IV_LENGTH);
  memcpy(ivByte, longToByte(iv), 8);

  CryptoPP::OFB_Mode<CryptoPP::AES>::Encryption prng;
  prng.SetKeyWithIV(seed, length, ivByte, IV_LENGTH);
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
  CryptoPP::byte *ivByte = new CryptoPP::byte[IV_LENGTH];
  memset(ivByte, 0x00, IV_LENGTH);
  memcpy(ivByte, longToByte(iv), 8);

  CryptoPP::OFB_Mode<CryptoPP::AES>::Encryption prng;
  prng.SetKeyWithIV(seed, SEED_LENGTH, ivByte, IV_LENGTH);

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
  Transform byte to block
*/
osuCrypto::block Util::byteToBlock(CryptoPP::byte* b, int length) {
  int blockLength = 8;
  osuCrypto::block output;
  int blockIndexesRequired = ceil(((float) length)/((float) blockLength));
  if(blockIndexesRequired>2) {
    cout << "Error! Block cannot be of length " << blockIndexesRequired << endl;
    throw;
  }
  for(int i=0; i<blockIndexesRequired; i++) {
    output[i] = byteToLong(b+(i*blockLength));
  }
  return output;
}

/*
  Transform block to byte
*/
CryptoPP::byte* Util::blockToByte(osuCrypto::block b, int length) {
  int blockLength = 8;
  int blockIndexesRequired = ceil(((float) length)/((float) blockLength));

  CryptoPP::byte *output = new CryptoPP::byte[length];

  for(int i=0; i<blockIndexesRequired; i++) {
    CryptoPP::byte *bytePart = Util::longToByte(b[i]);
    for(int j=0; j<blockLength; j++) {
      output[j+(i*blockLength)] = bytePart[j];
    }
  }
  return output;
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
  Transform long to byte (64 bits)
*/
CryptoPP::byte* Util::longToByte(long i) {
  CryptoPP::byte *b = new CryptoPP::byte[sizeof(long)];
  memcpy(b, &i, sizeof(long));
  return b;
}

/*
  Transform byte to long (64 bits)
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
  Merges multiple bytes to one
*/
CryptoPP::byte* Util::mergeBytes(vector<CryptoPP::byte*> bytes, int length) {
  int vectorLength = bytes.size();

  CryptoPP::byte* b = new CryptoPP::byte[vectorLength*length];
  for(int i=0; i<vectorLength; i++) {
    memcpy((b+(i*length)), bytes.at(i), length);
  }
  return b;
}

/*
  Transforms a byte to a string
*/
string Util::byteToString(CryptoPP::byte* b, int byteSize) {
  string output;
  CryptoPP::HexEncoder encoder;
  encoder.Put(b, byteSize);
  encoder.MessageEnd();
  CryptoPP::word64 s = encoder.MaxRetrievable();
  if(s) {
      output.resize(s);
      encoder.Get((CryptoPP::byte*)&output[0], output.size());
  }
  return output;
}

string Util::blockToString(osuCrypto::block b, int length) {
  return byteToString(blockToByte(b, length), length);
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
  CryptoPP::byte *output = new CryptoPP::byte[length];
  memcpy(output, b, length);

  return output;
}

osuCrypto::block Util::stringToBlock(string s, int length) {
  return byteToBlock(stringToByte(s, length), length);
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
  for(int i=length-1; i>=0; i--) {
    cout << intToBitString((long) b[i],8) << " ";
  }
  cout << endl;
}

void Util::printBlockInBits(osuCrypto::block b, int length) {
  CryptoPP::byte *byt = blockToByte(b, length);
  printByteInBits(byt, length);
}

string Util::byteToBitString(CryptoPP::byte* b, int length) {
  string out;
  for(int i=0; i<length; i++) {
    out += intToBitString((long) b[i],8)+" ";
  }
  return out;
}
