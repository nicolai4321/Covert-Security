#include "Util.h"
using namespace std;
using namespace std::chrono;

Util::Util() {}

/*
  Returns the least significant bit
*/
int Util::lsb(CryptoPP::byte* b, int length) {
  return stoi(bitset<1>(b[0]).to_string());
}

/*
  Bitwise operations:
*/
void Util::byteOp(CryptoPP::byte *b0, CryptoPP::byte *b1, CryptoPP::byte *output, int op, int length) {
  for(int i=0; i<length; i++) {
    if(op == XOR) {
      output[i] = b0[i] ^ b1[i];
    } else if(op == AND) {
      output[i] = b0[i] & b1[i];
    } else if(op == OR) {
      output[i] = b0[i] | b1[i];
    } else {
      throw runtime_error("Error! Unknown operator: '" + to_string(op) + "'");
    }
  }
}

/*
  Commit
*/
osuCrypto::Commit Util::commit(osuCrypto::block b, osuCrypto::block r) {
  return osuCrypto::Commit(b, r);
}

/*
  Commit
*/
osuCrypto::Commit Util::commit(vector<pair<CryptoPP::byte*,int>> bytes, osuCrypto::block r, int totalLength) {
  osuCrypto::u8 arr[totalLength];
  int index = 0;

  for(pair<CryptoPP::byte*,int> p : bytes) {
    CryptoPP::byte *b = p.first;
    int byteLength = p.second;

    for(int j=0; j<byteLength; j++) {
      arr[index] = b[j];
      index++;
    }
  }

  osuCrypto::span<osuCrypto::u8> s = {arr, totalLength};
  return osuCrypto::Commit(s, r);
}

/*
  Randomly shuffles a vector
*/
void Util::shuffle(vector<CryptoPP::byte*> v, CryptoPP::byte* seed, int seedLength, unsigned int iv) {
  //iv size is required to be 16 bytes
  CryptoPP::byte ivByte[IV_LENGTH];
  memset(ivByte, 0x00, IV_LENGTH);
  memcpy(ivByte, &iv, sizeof(unsigned int));

  CryptoPP::OFB_Mode<CryptoPP::AES>::Encryption prng;
  prng.SetKeyWithIV(seed, seedLength, ivByte, IV_LENGTH);
  prng.Shuffle(v.begin(), v.end());
}

/*
  Returns a random byte
*/
void Util::randomByte(CryptoPP::byte *output, int length) {
  CryptoPP::AutoSeededRandomPool asrp;
  asrp.GenerateBlock(output, length);
}

/*
  Returns a random byte with a seed
*/
unsigned int Util::randomByte(CryptoPP::byte *output, int length, CryptoPP::byte* seed, int seedLength, unsigned int iv) {
  //iv size is required to be 16 bytes
  CryptoPP::byte ivByte[IV_LENGTH];
  memset(ivByte, 0x00, IV_LENGTH);
  memcpy(ivByte, &iv, sizeof(unsigned int));

  CryptoPP::OFB_Mode<CryptoPP::AES>::Encryption prng;
  prng.SetKeyWithIV(seed, seedLength, ivByte, IV_LENGTH);
  prng.GenerateBlock(output, length);
  return iv+1;
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
long Util::randomInt(int minInt, int maxInt, CryptoPP::byte* seed, int length, unsigned int iv) {
  //iv size is required to be 16 bytes
  CryptoPP::byte ivByte[IV_LENGTH];
  memset(ivByte, 0x00, IV_LENGTH);
  memcpy(ivByte, &iv, sizeof(unsigned int));

  CryptoPP::OFB_Mode<CryptoPP::AES>::Encryption prng;
  prng.SetKeyWithIV(seed, length, ivByte, IV_LENGTH);

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
void Util::blockToByte(osuCrypto::block b, int length, CryptoPP::byte *output) {
  int blockLength = 8;
  int blockIndexesRequired = ceil(((float) length)/((float) blockLength));

  for(int i=0; i<blockIndexesRequired; i++) {
    memcpy(output+(i*blockLength), &b[i], blockLength);
  }
}

//Transform byte to integer (32 bits)
int Util::byteToInt(CryptoPP::byte* b) {
  int i;
  memcpy(&i, b, sizeof i);
  return i;
}

//Transform byte to long (64 bits)
long Util::byteToLong(CryptoPP::byte* b) {
  long i;
  memcpy(&i, b, sizeof(long));
  return i;
}

/*
  Merges two bytes to one
*/
void Util::mergeBytes(CryptoPP::byte *b0, CryptoPP::byte *b1, int length, CryptoPP::byte *output) {
  memcpy(output, b0, length);
  memcpy(output+length, b1, length);
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
  CryptoPP::byte byt[length];
  blockToByte(b, length, byt);
  return byteToString(byt, length);
}

/*
  Transform a string to a byte
*/
void Util::stringToByte(string s, CryptoPP::byte *output, int length) {
  string sink;
  CryptoPP::StringSink *stringSink = new CryptoPP::StringSink(sink);
  CryptoPP::HexDecoder *hexDecoder = new CryptoPP::HexDecoder(stringSink);
  CryptoPP::StringSource ss(s, true, hexDecoder);

  CryptoPP::byte *b = (CryptoPP::byte*) sink.data();
  memcpy(output, b, length);

  delete stringSink;
  delete hexDecoder;
}

osuCrypto::block Util::stringToBlock(string s, int length) {
  CryptoPP::byte output[length];
  stringToByte(s, output, length);
  return byteToBlock(output, length);
}

/*
  Prints a byte in string form
*/
void Util::printByte(CryptoPP::byte *b, int length) {
  string s;
  CryptoPP::StringSink *stringSink = new CryptoPP::StringSink(s);
  CryptoPP::HexEncoder *hexDecoder = new CryptoPP::HexEncoder(stringSink);
	CryptoPP::StringSource(b, length, true, hexDecoder);
  cout << "byte: " << s << endl;
  delete stringSink;
  delete hexDecoder;
}

void Util::printByteInBits(CryptoPP::byte *b, int length) {
  cout << "bits: ";
  for(int i=length-1; i>=0; i--) {
    cout << bitset<8>(b[i]).to_string() << " ";
  }
  cout << endl;
}

void Util::printBlockInBits(osuCrypto::block b, int length) {
  CryptoPP::byte byt[length];
  blockToByte(b, length, byt);
  printByteInBits(byt, length);
}

string Util::byteToBitString(CryptoPP::byte *b, int length) {
  string out;
  for(int i=0; i<length; i++) {
    out += bitset<8>(b[i]).to_string()+" ";
  }
  return out;
}
