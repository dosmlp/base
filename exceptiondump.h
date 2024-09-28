#ifndef EXCEPTIONDUMP_H
#define EXCEPTIONDUMP_H

#include <QtCore>
#include <Windows.h>

class ExceptionDump
{
public:
    ExceptionDump() = delete;
    void static Init(const QString& path,std::function<void ()> func = nullptr);

    void DisableSetUnhandledExceptionFilter();
    static long WINAPI ExceptionProcess(PEXCEPTION_POINTERS ExceptionInfo);
private:
    ExceptionDump(const QString& path,std::function<void ()> func);
    static ExceptionDump* self_;
    void* original_ = nullptr;
    QString path_;
    std::function<void ()> callback_func_;
};

#endif // EXCEPTIONDUMP_H
