#ifndef SOCKETRECORDER_H
#define SOCKETRECORDER_H
#include <map>
#include <string>
#include <vector>
#include "cryptoTools/Network/Channel.h"
using namespace osuCrypto;

class SocketRecorder : public SocketInterface {
public:
    SocketRecorder(osuCrypto::Channel chl) {
      mChl = chl;
    }

    ~SocketRecorder() override {}

    void async_send(span<boost::asio::mutable_buffer> buffers,
                    io_completion_handle&& fn) override {
      osuCrypto::error_code ec;
      u64 bytesTransfered = 0;
      for (u64 i = 0; i < u64( buffers.size()); ++i) {
          try {
              auto data = boost::asio::buffer_cast<u8*>(buffers[i]);
              auto siz = boost::asio::buffer_size(buffers[i]);

              CryptoPP::byte* b = new CryptoPP::byte[siz];
              memcpy(b, data, siz);

              pair<int, CryptoPP::byte*> p;
              p.first = siz;
              p.second = b;


              if(forceIterSentTotal == 0) {
                vector<pair<int, unsigned char*>> v = dataSentCat[sentCatIndex];
                v.push_back(p);
                dataSentCat[sentCatIndex] = v;
              } else {
                string index = forceIndex+to_string(forceIterSent);
                if(forceSent == 0) {
                  vector<pair<int, unsigned char*>> vIni;
                  dataSentCat[index] = vIni;
                  debugger.push_back(index);
                }
                vector<pair<int, unsigned char*>> v = dataSentCat[index];
                v.push_back(p);
                dataSentCat[index] = v;

                forceSent++;
                if(forceSent == forceSentTotal) {
                  forceSent = 0;
                  forceIterSent++;
                }

                if(forceIterSent == forceIterSentTotal) {
                  forceSentTotal = 0;
                  forceIterSentTotal = 0;
                }
              }

              mChl.send(data, siz);
              bytesTransfered += siz;
          } catch (...) {
              ec = boost::system::errc::make_error_code(boost::system::errc::io_error);
              break;
          }
      }
      fn(ec, bytesTransfered);
    }

    void async_recv(span<boost::asio::mutable_buffer> buffers,
                    io_completion_handle&& fn) override {
      osuCrypto::error_code ec;
      u64 bytesTransfered = 0;
      for (u64 i = 0; i < u64(buffers.size()); ++i) {
          try {
              auto data = boost::asio::buffer_cast<u8*>(buffers[i]);
              auto siz = boost::asio::buffer_size(buffers[i]);

              mChl.recv(data, siz);
              bytesTransfered += siz;

              CryptoPP::byte* b = new CryptoPP::byte[siz];
              memcpy(b, data, siz);
              pair<int, CryptoPP::byte*> p;
              p.first = siz;
              p.second = b;

              if(forceIterRecvTotal == 0) {
                vector<pair<int, unsigned char*>> v = dataRecvCat[recvCatIndex];
                v.push_back(p);
                dataRecvCat[recvCatIndex] = v;
              } else {
                string index = forceIndex+to_string(forceIterRecv);
                if(forceRecv == 0) {
                  vector<pair<int, unsigned char*>> vIni;
                  dataRecvCat[index] = vIni;
                  debugger.push_back(index);
                }
                vector<pair<int, unsigned char*>> v = dataRecvCat[index];
                v.push_back(p);
                dataRecvCat[index] = v;

                forceRecv++;
                if(forceRecv == forceRecvTotal) {
                  forceRecv = 0;
                  forceIterRecv++;
                }

                if(forceIterRecv == forceIterRecvTotal) {
                  forceRecvTotal = 0;
                  forceIterRecvTotal = 0;
                }
              }
          } catch (...) {
              ec = boost::system::errc::make_error_code(boost::system::errc::io_error);
              break;
          }
      }
      fn(ec, bytesTransfered);

    }

    void cancel() override {
        mChl.asyncCancel([](){});
    }

    osuCrypto::Channel getMChl() {
      return mChl;
    }

    //TODO remove debug function
    void check(string s) {
      if(s.empty()) throw runtime_error("Socket recorder cannot find record for empty string");
      bool b = false;
      for(string z : debugger) {
        if(z.compare(s) == 0) {
          b = true;
          break;
        }
      }
      if(!b) throw runtime_error("Socket recorder has no record for '"+s+"'");
    }

    vector<pair<int, unsigned char*>> getSentCat(string cat) {
      check(cat);
      vector<pair<int, unsigned char*>> output;
      for(pair<int, unsigned char*> p0 : dataSentCat[cat]) {
        pair<int, unsigned char*> p1;
        p1.first = p0.first;
        p1.second = p0.second;
        if(p1.first < 0) throw runtime_error("Error! Size for network data cannot be negative: "+to_string(p1.first));
        output.push_back(p1);
      }

      return output;
    }

    vector<pair<int, unsigned char*>> getRecvCat(string cat) {
      check(cat);
      vector<pair<int, unsigned char*>> output;
      for(pair<int, unsigned char*> p0 : dataRecvCat[cat]) {
        pair<int, unsigned char*> p1;
        p1.first = p0.first;
        p1.second = p0.second;
        if(p1.first < 0) throw runtime_error("Error! Size for network data cannot be negative: "+to_string(p1.first));
        output.push_back(p1);
      }

      return output;
    }

    void storeIn(string s) {
      for(string z : debugger) {
        if(z.compare(s) == 0) throw runtime_error("Error! Already using that storage");
      }

      debugger.push_back(s);
      sentCatIndex = s;
      recvCatIndex = s;
      vector<pair<int, unsigned char*>> v0;
      vector<pair<int, unsigned char*>> v1;
      dataSentCat[s] = v0;
      dataRecvCat[s] = v1;
    }

    void forceStore(string name, int iter, int nrSent, int nrRecv) {
      forceIndex = name;
      forceIterSentTotal = iter;
      forceIterRecvTotal = iter;
      forceIterSent = 0;
      forceIterRecv = 0;
      forceSentTotal = nrSent;
      forceRecvTotal = nrRecv;
      forceSent = 0;
      forceRecv = 0;
    }

  private:
    string forceIndex;
    int forceIterSentTotal = 0;
    int forceIterRecvTotal = 0;
    int forceIterSent = 0;
    int forceIterRecv = 0;
    int forceSentTotal = 0;
    int forceRecvTotal = 0;
    int forceSent = 0;
    int forceRecv = 0;

    osuCrypto::Channel mChl;
    map<string, vector<pair<int, unsigned char*>>> dataSentCat;
    map<string, vector<pair<int, unsigned char*>>> dataRecvCat;
    string sentCatIndex = "def";
    string recvCatIndex = "def";
    vector<string> debugger = {"def"};
};
#endif // SOCKETRECORDER_H
