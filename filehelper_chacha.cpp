#include "filehelper_chacha.h"

namespace spdlog {
namespace details {
static uint32_t CRYPTO_BUFFER_SIZE = 4096;


FileHelperChacha::FileHelperChacha(uint8_t *chacha_key, uint8_t *chacha_nonce, const file_event_handlers &event_headles)
    : event_handlers_(event_headles),
    crypto_buffer_(new uint8_t[CRYPTO_BUFFER_SIZE])
{
    if (chacha_key == nullptr || chacha_nonce == nullptr) {
        throw_spdlog_ex("chacha key or nonce is null.");
        std::memset(key_, 0, 32);
        std::memset(nonce_, 0, 12);
    } else {
        std::memcpy(key_, chacha_key, 32);
        std::memcpy(nonce_, chacha_nonce, 12);
    }

}

FileHelperChacha::~FileHelperChacha()
{
    close();
}
void FileHelperChacha::init_chacha20()
{
    //前四个字节全为0分隔每次加密的数据,后四个字节表示每次总计加密的数据大小
    unsigned char data[8] = {0,0,0,0,0xFF,0xFF,0xFF,0xFF};
    if (std::fwrite(data, 1, 8, fd_) != 8) {
        throw_spdlog_ex("Failed writing to file " + os::filename_to_str(filename_));
    }
    /*不记录加密大小
    total_write_ = 0;
    std::fpos_t pos;
    if (std::fgetpos(fd_, &pos) != 0) {
        throw_spdlog_ex("Failed getpos " + os::filename_to_str(filename_));
    }
#ifdef __linux__
    size_pos_.__pos = pos.__pos - 4;
#else
    size_pos_ = pos - 4;
#endif
*/
    if (!chacha20_ctx_) {
        chacha20_ctx_ = new mbedtls_chacha20_context;
    } else {
        delete chacha20_ctx_;
        chacha20_ctx_ = new mbedtls_chacha20_context;
    }
    mbedtls_chacha20_init(chacha20_ctx_);
    mbedtls_chacha20_setkey(chacha20_ctx_,key_);
    mbedtls_chacha20_starts(chacha20_ctx_,nonce_,0);
}
void FileHelperChacha::open(const filename_t &fname, bool truncate)
{
    close();
    filename_ = fname;

    auto *mode = SPDLOG_FILENAME_T("ab");
    auto *trunc_mode = SPDLOG_FILENAME_T("wb");

    if (event_handlers_.before_open)
    {
        event_handlers_.before_open(filename_);
    }

    for (int tries = 0; tries < open_tries_; ++tries)
    {
        // create containing folder if not exists already.
        os::create_dir(os::dir_name(fname));
        if (truncate)
        {
            // Truncate by opening-and-closing a tmp file in "wb" mode, always
            // opening the actual log-we-write-to in "ab" mode, since that
            // interacts more politely with eternal processes that might
            // rotate/truncate the file underneath us.
            std::FILE *tmp;
            if (os::fopen_s(&tmp, fname, trunc_mode))
            {
                continue;
            }
            std::fclose(tmp);
        }
        if (!os::fopen_s(&fd_, fname, mode))
        {
            if (event_handlers_.after_open)
            {
                event_handlers_.after_open(filename_, fd_);
            }
            init_chacha20();
            return;
        }

        details::os::sleep_for_millis(open_interval_);
    }

    throw_spdlog_ex("Failed opening file " + os::filename_to_str(filename_) + " for writing", errno);
}

void FileHelperChacha::reopen(bool truncate)
{
    if (filename_.empty())
    {
        throw_spdlog_ex("Failed re opening file - was not opened before");
    }
    this->open(filename_, truncate);
}

void FileHelperChacha::flush()
{
    std::fflush(fd_);
}

void FileHelperChacha::close()
{
    if (chacha20_ctx_ != nullptr) {
        delete chacha20_ctx_;
        chacha20_ctx_ = nullptr;
    }
    if (fd_ != nullptr)
    {
        if (event_handlers_.before_close)
        {
            event_handlers_.before_close(filename_, fd_);
        }

        std::fclose(fd_);
        fd_ = nullptr;

        if (event_handlers_.after_close)
        {
            event_handlers_.after_close(filename_);
        }
    }
}

void FileHelperChacha::write(const memory_buf_t &buf)
{
    size_t msg_size = buf.size();
    auto data = buf.data();
    if (msg_size > CRYPTO_BUFFER_SIZE) {
        crypto_buffer_.reset(new uint8_t[msg_size]);
    }
    mbedtls_chacha20_update(chacha20_ctx_,msg_size,(const uint8_t*)data,crypto_buffer_.get());
    if (std::fwrite(crypto_buffer_.get(), 1, msg_size, fd_) != msg_size)
    {
        throw_spdlog_ex("Failed writing to file " + os::filename_to_str(filename_), errno);
    }
    //total_write_ += msg_size;
}

size_t FileHelperChacha::size() const
{
    if (fd_ == nullptr)
    {
        throw_spdlog_ex("Cannot use size() on closed file " + os::filename_to_str(filename_));
    }
    return os::filesize(fd_);
}

const filename_t &FileHelperChacha::filename() const
{
    return filename_;
}

std::tuple<filename_t, filename_t> FileHelperChacha::split_by_extension(const filename_t &fname)
{
    auto ext_index = fname.rfind('.');

    // no valid extension found - return whole path and empty string as
    // extension
    if (ext_index == filename_t::npos || ext_index == 0 || ext_index == fname.size() - 1)
    {
        return std::make_tuple(fname, filename_t());
    }

    // treat cases like "/etc/rc.d/somelogfile or "/abc/.hiddenfile"
    auto folder_index = fname.find_last_of(details::os::folder_seps_filename);
    if (folder_index != filename_t::npos && folder_index >= ext_index - 1)
    {
        return std::make_tuple(fname, filename_t());
    }

    // finally - return a valid base and extension tuple
    return std::make_tuple(fname.substr(0, ext_index), fname.substr(ext_index));
}
}
}
