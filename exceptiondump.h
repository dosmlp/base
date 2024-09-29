#ifndef EXCEPTIONDUMP_H
#define EXCEPTIONDUMP_H

#include <QtCore>
#include <Windows.h>

class ExceptionDump
{
public:

    //非线程安全，仅能调用一次，请在程序运行最开始调用
    void static Init(const QString& path, std::function<void (void*)> func = nullptr, void *userdata = nullptr);

    void DisableSetUnhandledExceptionFilter();
    static long WINAPI ExceptionProcess(PEXCEPTION_POINTERS ExceptionInfo);
private:
    ExceptionDump() = delete;
    ExceptionDump(const QString& path, std::function<void (void *)> func, void* userdata);
    static ExceptionDump* self_;
    void* original_ = nullptr;
    QString path_;
    QString app_dirpath_;
    std::function<void (void*)> callback_func_;
    static void* userdata_;
};

#endif // EXCEPTIONDUMP_H
