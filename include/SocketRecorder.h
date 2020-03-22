#ifndef SOCKETRECORDER_H
#define SOCKETRECORDER_H
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
              dataSent.push_back(p);

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

              CryptoPP::byte* b = new CryptoPP::byte[siz];
              memcpy(b, data, siz);
              pair<int, CryptoPP::byte*> p;
              p.first = siz;
              p.second = b;
              dataRecv.push_back(p);

              mChl.recv(data, siz);
              bytesTransfered += siz;
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

    void clearDataSent() {
      sentIndex = dataSent.size();
    }

    void clearDataRecv() {
      recvIndex = dataRecv.size();
    }

    vector<pair<int, unsigned char*>> getDataSent() {
      vector<pair<int, unsigned char*>> output;
      for(int i=sentIndex; i<dataSent.size(); i++) {
        output.push_back(dataSent.at(i));
      }
      return output;
    }

    vector<pair<int, unsigned char*>> getDataRecv() {
      vector<pair<int, unsigned char*>> output;
      for(int i=recvIndex; i<dataRecv.size(); i++) {
        output.push_back(dataRecv.at(i));
      }
      return output;
    }

    osuCrypto::Channel getMChl() {
      return mChl;
    }

  private:
    osuCrypto::Channel mChl;
    vector<pair<int, unsigned char*>> dataSent;
    vector<pair<int, unsigned char*>> dataRecv;
    int sentIndex = 0;
    int recvIndex = 0;
};
#endif // SOCKETRECORDER_H
