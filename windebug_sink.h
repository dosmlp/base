// Copyright(c) 2016 Alexander Dalshov.
// Distributed under the MIT License (http://opensource.org/licenses/MIT)

#pragma once

#if defined(_WIN32)

#    include <spdlog/details/null_mutex.h>
#    include <spdlog/sinks/base_sink.h>

#    include <mutex>
#    include <string>

// Avoid including windows.h (https://stackoverflow.com/a/30741042)
extern "C" __declspec(dllimport) void __stdcall OutputDebugStringA(const char *lpOutputString);
extern "C" __declspec(dllimport) void __stdcall OutputDebugStringW(LPCWSTR lpOutputString);

namespace spdlog {
namespace sinks {
/*
 * MSVC sink (logging using OutputDebugStringA)
 */
template<typename Mutex>
class windebug_sink : public base_sink<Mutex>
{
public:
    windebug_sink()
    {
        wstr = new wchar_t[str_size];
    }
    ~windebug_sink()
    {
        delete[] wstr;
        wstr = nullptr;
    }

protected:
    void sink_it_(const details::log_msg &msg) override
    {
        memory_buf_t formatted;
        base_sink<Mutex>::formatter_->format(msg, formatted);
        formatted.push_back('\0'); // add a null terminator for OutputDebugStringA

        //utf8转utf16,qtcreator控制台输出编码为utf16
        int wchar_size = MultiByteToWideChar(CP_UTF8,0,formatted.data(),-1,NULL,0);
        if (wchar_size > str_size) {
            str_size = wchar_size;
            delete[] wstr;
            wstr = new wchar_t[str_size];
        }
        MultiByteToWideChar(CP_UTF8,0,formatted.data(),-1,wstr,wchar_size);

        OutputDebugStringW(wstr);
    }

    void flush_() override {}
private:
    wchar_t* wstr;
    int str_size = 1024;
};

using windebug_sink_mt = windebug_sink<std::mutex>;
using windebug_sink_st = windebug_sink<details::null_mutex>;


} // namespace sinks
} // namespace spdlog

#endif
