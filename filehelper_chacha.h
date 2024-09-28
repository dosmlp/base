#ifndef FILEHELPER_CHACHA_H
#define FILEHELPER_CHACHA_H
#include <spdlog/spdlog.h>
extern "C" {
#include <mbedtls/chacha20.h>
}

namespace spdlog {
namespace details {
class FileHelperChacha
{
public:
    explicit FileHelperChacha(uint8_t* chacha_key,uint8_t* chacha_nonce,
                              const file_event_handlers &event_handlers);

    FileHelperChacha(const FileHelperChacha &) = delete;
    FileHelperChacha &operator=(const FileHelperChacha &) = delete;
    ~FileHelperChacha();

    void open(const filename_t &fname, bool truncate = false);
    void reopen(bool truncate);
    void flush();
    void close();
    void write(const memory_buf_t &buf);
    size_t size() const;
    const filename_t &filename() const;
    static std::tuple<filename_t, filename_t> split_by_extension(const filename_t &fname);

private:
    void init_chacha20();
    const int open_tries_ = 5;
    const unsigned int open_interval_ = 10;
    std::FILE *fd_{nullptr};
    filename_t filename_;
    file_event_handlers event_handlers_;
    //chacha20
    mbedtls_chacha20_context* chacha20_ctx_ = nullptr;
    std::unique_ptr<uint8_t> crypto_buffer_;
    uint8_t key_[32];
    uint8_t nonce_[12];
};
}//details

}//spdlog
#endif // FILEHELPER_CHACHA_H
