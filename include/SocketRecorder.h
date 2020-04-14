#ifndef SOCKETRECORDER_H
#define SOCKETRECORDER_H
#include <map>
#include <string>
#include <vector>
#include "cryptoTools/Network/Channel.h"
using namespace osuCrypto;

class SocketRecorder : public SocketInterface {
public:
    void async_send(span<boost::asio::mutable_buffer> buffers,
                    io_completion_handle&& fn) override {
      osuCrypto::error_code ec;
      u64 bytesTransfered = 0;
      for (u64 i = 0; i < u64( buffers.size()); ++i) {
          try {
              auto data = boost::asio::buffer_cast<u8*>(buffers[i]);
              auto siz = boost::asio::buffer_size(buffers[i]);

              CryptoPP::byte *b = new CryptoPP::byte[siz];
              memcpy(b, data, siz);

              pair<int, CryptoPP::byte*> p;
              p.first = siz;
              p.second = b;

              if(scheduleIterSentTotal  == 0) {
                vector<pair<int, unsigned char*>> v = dataSentCat[sentCatIndex];
                v.push_back(p);
                dataSentCat[sentCatIndex] = v;
                if(name.compare("none") != 0) {
                  cout << name << " send (" << siz << "), storing in '" << sentCatIndex << "'" << endl;
                }
              } else {
                string index = scheduleIndex+to_string(scheduleIterSent);
                if(scheduleSent == 0) {
                  vector<pair<int, unsigned char*>> vIni;
                  dataSentCat[index] = vIni;
                  debugger.push_back(index);
                }
                vector<pair<int, unsigned char*>> v = dataSentCat[index];
                v.push_back(p);
                dataSentCat[index] = v;

                if(name.compare("none") != 0) {
                  cout << name << " send (" << siz << "), storing in '" << index << "'" << endl;
                }

                scheduleSent++;
                if(scheduleSent == scheduleSentTotal) {
                  scheduleSent = 0;
                  scheduleIterSent++;
                }

                if(scheduleIterSent == scheduleIterSentTotal ) {
                  scheduleSentTotal = 0;
                  scheduleIterSentTotal  = 0;
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

              CryptoPP::byte *b = new CryptoPP::byte[siz];
              memcpy(b, data, siz);
              pair<int, CryptoPP::byte*> p;
              p.first = siz;
              p.second = b;

              if(scheduleIterRecvTotal == 0) {
                vector<pair<int, unsigned char*>> v = dataRecvCat[recvCatIndex];
                v.push_back(p);
                dataRecvCat[recvCatIndex] = v;
                if(name.compare("none") != 0) {
                  cout << name << " recv(" << siz << ") storing in '" << recvCatIndex << "'" << endl;
                }
              } else {
                string index = scheduleIndex+to_string(scheduleIterRecv);
                if(scheduleRecv == 0) {
                  vector<pair<int, unsigned char*>> vIni;
                  dataRecvCat[index] = vIni;
                  debugger.push_back(index);
                }
                vector<pair<int, unsigned char*>> v = dataRecvCat[index];
                v.push_back(p);
                dataRecvCat[index] = v;
                if(name.compare("none") != 0) {
                  cout << name << " recv(" << siz << ") storing in '" << index << "'" << endl;
                }

                scheduleRecv++;
                if(scheduleRecv == scheduleRecvTotal) {
                  scheduleRecv = 0;
                  scheduleIterRecv++;
                }

                if(scheduleIterRecv == scheduleIterRecvTotal) {
                  scheduleRecvTotal = 0;
                  scheduleIterRecvTotal = 0;
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

    void getSentCat(string cat, vector<pair<int, unsigned char*>> *lst) {
      check(cat);
      for(pair<int, unsigned char*> p0 : dataSentCat[cat]) {
        pair<int, unsigned char*> p1;
        p1.first = p0.first;
        p1.second = p0.second;
        if(p1.first < 0) throw runtime_error("Error! Size for network data cannot be negative: "+to_string(p1.first));
        lst->push_back(p1);
      }
    }

    void getRecvCat(string cat, vector<pair<int, unsigned char*>> *lst) {
      check(cat);
      for(pair<int, unsigned char*> p0 : dataRecvCat[cat]) {
        pair<int, unsigned char*> p1;
        p1.first = p0.first;
        p1.second = p0.second;
        if(p1.first < 0) throw runtime_error("Error! Size for network data cannot be negative: "+to_string(p1.first));
        lst->push_back(p1);
      }
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

    void scheduleStore(string name, int iter, int nrSent, int nrRecv) {
      scheduleIndex = name;
      scheduleIterSentTotal = iter;
      scheduleIterRecvTotal = iter;
      scheduleIterSent = 0;
      scheduleIterRecv = 0;
      scheduleSentTotal = nrSent;
      scheduleRecvTotal = nrRecv;
      scheduleSent = 0;
      scheduleRecv = 0;
    }

    void follow(string s) {
      name = s;
    }

    SocketRecorder(osuCrypto::Channel chl) {
      mChl = chl;
    }

    ~SocketRecorder() override {
      map<string, vector<pair<int, unsigned char*>>>::iterator itSent;
      for(itSent = dataSentCat.begin(); itSent != dataSentCat.end(); itSent++) {
        vector<pair<int, unsigned char*>> v = itSent->second;
        for(pair<int, unsigned char*> p : v) {
          delete p.second;
        }
      }

      map<string, vector<pair<int, unsigned char*>>>::iterator itRecv;
      for(itRecv = dataRecvCat.begin(); itRecv != dataRecvCat.end(); itRecv++) {
        vector<pair<int, unsigned char*>> v = itRecv->second;
        for(pair<int, unsigned char*> p : v) {
          delete p.second;
        }
      }
    }

  private:
    string name = "none";

    string scheduleIndex;
    int scheduleIterSentTotal = 0;
    int scheduleIterRecvTotal = 0;
    int scheduleIterSent = 0;
    int scheduleIterRecv = 0;
    int scheduleSentTotal = 0;
    int scheduleRecvTotal = 0;
    int scheduleSent = 0;
    int scheduleRecv = 0;

    osuCrypto::Channel mChl;
    map<string, vector<pair<int, unsigned char*>>> dataSentCat;
    map<string, vector<pair<int, unsigned char*>>> dataRecvCat;
    string sentCatIndex = "def";
    string recvCatIndex = "def";
    vector<string> debugger = {"def"};
};
#endif // SOCKETRECORDER_H
