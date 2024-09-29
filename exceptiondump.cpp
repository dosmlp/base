#include "exceptiondump.h"
#include <QDateTime>
// #include <QMessageBox>
#include <QDir>
#include <DbgHelp.h>
#include <debugapi.h>
#include <TlHelp32.h>
#include <tchar.h>
#include <QStandardPaths>
extern "C" {
#include "MinHook.h"
}
#include <chrono>

ExceptionDump* ExceptionDump::self_ = nullptr;

typedef BOOL (WINAPI *ENUMERATELOADEDMODULES64)(HANDLE process,
        PENUMLOADED_MODULES_CALLBACK64 enum_loaded_modules_callback,
        PVOID user_context);
typedef DWORD (WINAPI *SYMSETOPTIONS)(DWORD sym_options);
typedef BOOL (WINAPI *SYMINITIALIZE)(HANDLE hProcess,PCWSTR UserSearchPath,BOOL fInvadeProcess);
typedef BOOL (WINAPI *SYMCLEANUP)(HANDLE process);
typedef BOOL (WINAPI *STACKWALK64)(DWORD machine_type, HANDLE process,
        HANDLE thread, LPSTACKFRAME64 stack_frame,
        PVOID context_record,
        PREAD_PROCESS_MEMORY_ROUTINE64 read_memory_routine,
        PFUNCTION_TABLE_ACCESS_ROUTINE64 function_table_access_routine,
        PGET_MODULE_BASE_ROUTINE64 get_module_base_routine,
        PTRANSLATE_ADDRESS_ROUTINE64 translate_address);
typedef BOOL (WINAPI *SYMREFRESHMODULELIST)(HANDLE process);

typedef PVOID (WINAPI *SYMFUNCTIONTABLEACCESS64)(HANDLE process,
        DWORD64 addr_base);
typedef DWORD64 (WINAPI *SYMGETMODULEBASE64)(HANDLE process, DWORD64 addr);
typedef BOOL (WINAPI *SYMFROMADDR)(HANDLE process, DWORD64 address,
        PDWORD64 displacement, PSYMBOL_INFOW symbol);
typedef BOOL (WINAPI *SYMGETMODULEINFO64)(HANDLE process, DWORD64 addr,
        PIMAGEHLP_MODULEW64 module_info);

typedef DWORD64 (WINAPI *SYMLOADMODULE64)(HANDLE process, HANDLE file,
        PSTR image_name, PSTR module_name, DWORD64 base_of_dll,
        DWORD size_of_dll);

typedef BOOL (WINAPI *MINIDUMPWRITEDUMP)(HANDLE process, DWORD process_id,
        HANDLE file, MINIDUMP_TYPE dump_type,
        PMINIDUMP_EXCEPTION_INFORMATION exception_param,
        PMINIDUMP_USER_STREAM_INFORMATION user_stream_param,
        PMINIDUMP_CALLBACK_INFORMATION callback_param);

typedef HINSTANCE (WINAPI *SHELLEXECUTEA)(HWND hwnd, LPCTSTR operation,
        LPCTSTR file, LPCTSTR parameters, LPCTSTR directory,
        INT show_flags);

typedef BOOL (WINAPI *SYMGETLINEFROMADDRW64)(
         HANDLE hProcess,
         DWORD64 dwAddr,
         PDWORD pdwDisplacement,
         PIMAGEHLP_LINEW64 Line);

struct StackTrace {
    CONTEXT                               context;
    DWORD64                               instruction_ptr;
    STACKFRAME64                          frame;
    DWORD                                 image_type;
};

struct ModuleInfo {
    DWORD64 addr;
    char name_utf8[MAX_PATH];
};


struct ExceptionHandlerData {
    typedef std::shared_ptr<ExceptionHandlerData> ptr;
    static ptr make()
    {
        return std::make_shared<ExceptionHandlerData>();
    }
    ExceptionHandlerData()
    {}
    ~ExceptionHandlerData()
    {
        if (sym_info) LocalFree(sym_info);
        if (dbghelp) FreeLibrary(dbghelp);
    }
    SYMINITIALIZE                         sym_initialize = nullptr;
    SYMCLEANUP                            sym_cleanup = nullptr;
    SYMSETOPTIONS                         sym_set_options = nullptr;
    SYMFUNCTIONTABLEACCESS64              sym_function_table_access64 = nullptr;
    SYMGETMODULEBASE64                    sym_get_module_base64 = nullptr;
    SYMFROMADDR                           sym_from_addr = nullptr;
    SYMGETMODULEINFO64                    sym_get_module_info64 = nullptr;
    SYMREFRESHMODULELIST                  sym_refresh_module_list = nullptr;
    STACKWALK64                           stack_walk64 = nullptr;
    ENUMERATELOADEDMODULES64              enumerate_loaded_modules64 = nullptr;
    MINIDUMPWRITEDUMP                     minidump_write_dump = nullptr;
    SYMGETLINEFROMADDRW64                 sym_get_line_from_addr = nullptr;

    HMODULE                               dbghelp = 0;
    SYMBOL_INFOW                          *sym_info = 0;
    PEXCEPTION_POINTERS                   exception = nullptr;
    SYSTEMTIME                            time_info;
    HANDLE                                process = nullptr;

    StackTrace                            main_trace;

    QString                           str;
    QString                           cpu_info;
    QString                           module_name;
    QString                           module_list;
    QString                           file_name;
};

static void *GetProc(HMODULE module, const char *func)
{
    return (void*)GetProcAddress(module, func);
}

static bool GetDbghelpImports(struct ExceptionHandlerData *data)
{
    data->dbghelp = LoadLibraryA("dbghelp.dll");
    if (!data->dbghelp)
        return false;

    data->sym_initialize= (SYMINITIALIZE)GetProc(data->dbghelp,"SymInitializeW");
    data->sym_cleanup= (SYMCLEANUP)GetProc(data->dbghelp,"SymCleanup");
    data->sym_set_options= (SYMSETOPTIONS)GetProc(data->dbghelp,"SymSetOptions");
    data->sym_function_table_access64= (SYMFUNCTIONTABLEACCESS64)GetProc(data->dbghelp,"SymFunctionTableAccess64");
    data->sym_get_module_base64= (SYMGETMODULEBASE64)GetProc(data->dbghelp,"SymGetModuleBase64");
    data->sym_from_addr= (SYMFROMADDR)GetProc(data->dbghelp,"SymFromAddrW");
    data->sym_get_module_info64= (SYMGETMODULEINFO64)GetProc(data->dbghelp,"SymGetModuleInfoW64");
    data->sym_refresh_module_list= (SYMREFRESHMODULELIST)GetProc(data->dbghelp,"SymRefreshModuleList");
    data->stack_walk64= (STACKWALK64)GetProc(data->dbghelp,"StackWalk64");
    data->enumerate_loaded_modules64= (ENUMERATELOADEDMODULES64)GetProc(data->dbghelp,"EnumerateLoadedModulesW64");
    data->minidump_write_dump= (MINIDUMPWRITEDUMP)GetProc(data->dbghelp,"MiniDumpWriteDump");
    data->sym_get_line_from_addr= (SYMGETLINEFROMADDRW64)GetProc(data->dbghelp,"SymGetLineFromAddrW64");

    return true;
}
static unsigned int wchar_to_utf8(const wchar_t *in, unsigned int insize, char *out,
                           unsigned int outsize, int flags)
{
   int i_insize = (int)insize;
   int ret;

   if (i_insize == 0)
       i_insize = (int)wcslen(in);

   ret = WideCharToMultiByte(CP_UTF8, 0, in, i_insize, out, (int)outsize,
           NULL, NULL);


   return (ret > 0) ? (unsigned int)ret : 0;
}

static unsigned int os_wcs_to_utf8(const wchar_t *str, unsigned int len, char *dst,
        unsigned int dst_size)
{
    unsigned int in_len;
    unsigned int out_len;

    if (!str)
        return 0;

    in_len = (len != 0) ? len : wcslen(str);
    out_len = dst ? (dst_size - 1) : wchar_to_utf8(str, in_len, NULL, 0, 0);

    if (dst) {
        if (!dst_size)
            return 0;

        if (out_len)
            out_len = wchar_to_utf8(str, in_len,
                    dst, out_len + 1, 0);

        dst[out_len] = 0;
    }

    return out_len;
}
static void InitSymInfo(ExceptionHandlerData *data)
{
    data->sym_set_options(
            SYMOPT_UNDNAME |
            SYMOPT_FAIL_CRITICAL_ERRORS |
            SYMOPT_LOAD_ANYTHING);
    //符号初始化
    BOOL ret = data->sym_initialize(data->process, NULL, TRUE);
//    if (!sym_initialize_called)
//        data->sym_initialize(data->process, NULL, true);
//    else
//        data->sym_refresh_module_list(data->process);

    data->sym_info = (SYMBOL_INFOW*)LocalAlloc(LPTR, sizeof(*data->sym_info) + 256);
    data->sym_info->SizeOfStruct = sizeof(SYMBOL_INFO);
    data->sym_info->MaxNameLen = 256;
}

#define PROCESSOR_REG_KEY L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"
#define CPU_ERROR "<unable to query>"

static void InitCpuInfo(ExceptionHandlerData *data)
{
    HKEY key;
    LSTATUS status;

    status = RegOpenKeyW(HKEY_LOCAL_MACHINE, PROCESSOR_REG_KEY, &key);
    if (status == ERROR_SUCCESS)
    {
        wchar_t str[1024];
        DWORD size = 1024;

        status = RegQueryValueExW(key, L"ProcessorNameString", NULL,
                NULL, (LPBYTE)str, &size);
        if (status == ERROR_SUCCESS)
            data->cpu_info = QString::fromUtf16((const ushort*)str);
        else
            data->cpu_info = CPU_ERROR;
    }
    else
    {
        data->cpu_info = CPU_ERROR;
    }
}

static void InitInstructionData(StackTrace *trace)
{
#ifdef _WIN64
    trace->instruction_ptr = trace->context.Rip;
    trace->frame.AddrPC.Offset = trace->instruction_ptr;
    trace->frame.AddrFrame.Offset = trace->context.Rbp;
    trace->frame.AddrStack.Offset = trace->context.Rsp;
    trace->image_type = IMAGE_FILE_MACHINE_AMD64;
#else
    trace->instruction_ptr = trace->context.Eip;//eip 即将要执行指令的地址
    trace->frame.AddrPC.Offset = trace->context.Eip;//发生异常的地址
    trace->frame.AddrFrame.Offset = trace->context.Ebp;
    trace->frame.AddrStack.Offset = trace->context.Esp;//栈顶的地址
    trace->image_type = IMAGE_FILE_MACHINE_I386;
#endif

    trace->frame.AddrFrame.Mode = AddrModeFlat;
    trace->frame.AddrPC.Mode = AddrModeFlat;
    trace->frame.AddrStack.Mode = AddrModeFlat;
}

static void WriteHeader(ExceptionHandlerData *data)
{
    char date_time[80];
    time_t now = time(0);
    struct tm ts;
    ts = *localtime(&now);
    strftime(date_time, sizeof(date_time), "%Y-%m-%d, %X", &ts);


    data->str += "Unhandled exception: ";
    data->str += QString::number(data->exception->ExceptionRecord->ExceptionCode,16);
    data->str += "\n";
    data->str += "Date/Time: ";
    data->str += QString(date_time);
    data->str += "\n";
    data->str += "Fault address: ";
    data->str += QString::number(data->main_trace.instruction_ptr,16);
    data->str += "\n";
    data->str += "CPU: ";
    data->str += data->cpu_info;
    data->str += "\n";

    IMAGEHLP_LINEW64 lineInfo = { 0 };
    lineInfo.SizeOfStruct = sizeof(IMAGEHLP_LINEW64);
    DWORD displacement = 0;
    BOOL ret = data->sym_get_line_from_addr(data->process,data->main_trace.instruction_ptr-1,&displacement,&lineInfo);
    if (ret) {
        data->str += "Exception Source File:";

        QString fileName = QString::fromUtf16((const char16_t*)lineInfo.FileName);
        int slashPos = fileName.lastIndexOf('\\');
        if(slashPos != -1)
            fileName = fileName.mid(slashPos + 1);

        data->str += fileName + ":" +QString::number(lineInfo.LineNumber);
    }

}
static BOOL CALLBACK EnumModuleCallBack(PCTSTR module_name, DWORD64 module_base,
        ULONG module_size, struct ModuleInfo *info)
{
    if (info->addr >= module_base &&
        info->addr <  module_base + module_size) {

        os_wcs_to_utf8(module_name, 0, info->name_utf8, MAX_PATH);
        strlwr(info->name_utf8);
        return false;
    }

    return true;
}

static inline void GetModuleName(ExceptionHandlerData *data, ModuleInfo *info)
{
    data->enumerate_loaded_modules64(data->process,
            (PENUMLOADED_MODULES_CALLBACK64)EnumModuleCallBack, info);
}
static inline bool WalkStack(ExceptionHandlerData *data,
                             HANDLE thread, StackTrace *trace)
{
    // ModuleInfo module_info = {0};
    DWORD64 func_offset;
    char sym_name[256];
    // char *p;
    bool success = data->stack_walk64(trace->image_type,
                                      data->process,
                                      thread,
                                      &trace->frame,
                                      &trace->context,
                                      NULL, data->sym_function_table_access64,
                                      data->sym_get_module_base64, NULL);
    if (!success)
        return false;
    // module_info.addr = trace->frame.AddrPC.Offset;
    // GetModuleName(data, &module_info);

    IMAGEHLP_MODULEW64 mod;
    mod.SizeOfStruct = sizeof(IMAGEHLP_MODULEW64);
    data->sym_get_module_info64(data->process, trace->frame.AddrPC.Offset, &mod);
    QString fileName = QString::fromUtf16((const char16_t*)mod.ImageName);
    int slashPos = fileName.lastIndexOf('\\');
    if(slashPos != -1)
        fileName = fileName.mid(slashPos + 1);

    // if (!!module_info.name_utf8[0]) {
    //     p = strrchr(module_info.name_utf8, '\\');
    //     p = p ? (p + 1) : module_info.name_utf8;
    // } else {
    //     strcpy(module_info.name_utf8, "<unknown>");
    //     p = module_info.name_utf8;
    // }

    success = !!data->sym_from_addr(data->process,
                                    trace->frame.AddrPC.Offset, &func_offset,
                                    data->sym_info);

    DWORD displacement = 0;
    IMAGEHLP_LINEW64 lineInfo = { 0 };
    lineInfo.SizeOfStruct = sizeof(IMAGEHLP_LINEW64);
    BOOL ret = data->sym_get_line_from_addr(data->process,trace->frame.AddrPC.Offset-1,&displacement,&lineInfo);
    if (ret) {
        data->str += QString::fromWCharArray((wchar_t*)lineInfo.FileName) +":"+QString::number(lineInfo.LineNumber)+"\n";
    } else {
        data->str += "unknown:unknown\n";
    }


    if (success)
        os_wcs_to_utf8(data->sym_info->Name, 0, sym_name, 256);

    if (success && (data->sym_info->Flags & SYMFLAG_EXPORT) == 0) {
        data->str += fileName+"!"+QString(sym_name)+"!0x"+QString::number(func_offset,16)+"\n";
    } else {
        data->str += "EIP:0x"+QString::number(trace->frame.AddrPC.Offset,16)+"\n";
    }

    return true;
}
static void WriteThreadTrace(ExceptionHandlerData *data,
                             THREADENTRY32 *entry, bool first_thread)
{
    //该线程是否是发生异常的线程
    bool crash_thread = entry->th32ThreadID == GetCurrentThreadId();
    StackTrace trace = {0};
    StackTrace *ptrace;
    HANDLE thread;

    if (first_thread != crash_thread)
        return;

    if (entry->th32OwnerProcessID != GetCurrentProcessId())
        return;

    thread = OpenThread(THREAD_ALL_ACCESS, false, entry->th32ThreadID);
    if (!thread)
        return;

    trace.context.ContextFlags = CONTEXT_ALL;
    /* 每个线程都有一个上下文环境，它包含了有关线程的大部分信息，例如线程栈的地址，线程当前正在执行的指令地址等。
     上下文环境保存在寄存器中，系统进行线程调度的时候会发生上下文切换，实际上就是将一个线程的上下文环境保存到内存中，
     然后将另一个线程的上下文环境装入寄存器。 */
    GetThreadContext(thread, &trace.context);
    InitInstructionData(&trace);

    data->str += "\n=================Thread "+QString::number(entry->th32ThreadID)+(crash_thread?" (Crashed)\n":"\n");

    ptrace = crash_thread ? &data->main_trace : &trace;
    //遍历堆栈
    while (WalkStack(data, thread, ptrace));

    CloseHandle(thread);

}

//枚举线程
static void WriteThreadTraces(ExceptionHandlerData *data)
{
    THREADENTRY32 entry = {0};
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,
                                               GetCurrentProcessId());
    bool success;

    if (snapshot == INVALID_HANDLE_VALUE)
        return;

    entry.dwSize = sizeof(entry);
    success = !!Thread32First(snapshot, &entry);
    while (success) {
        //找到发生异常的线程
        WriteThreadTrace(data, &entry, true);
        success = !!Thread32Next(snapshot, &entry);
    }
//    success = !!Thread32First(snapshot, &entry);
//    //遍历其他线程
//    while (success) {
//        WriteThreadTrace(data, &entry, false);
//        success = !!Thread32Next(snapshot, &entry);
//    }
    CloseHandle(snapshot);
}

static void HandleException(ExceptionHandlerData *data,
        PEXCEPTION_POINTERS exception)
{
    //获取在dbghelp中要用到的函数地址
    if (!GetDbghelpImports(data)) {
        return;
    }
    data->exception = exception;
    data->process = GetCurrentProcess();
    data->main_trace.context = *exception->ContextRecord;
    GetSystemTime(&data->time_info);

    //加载符号
    InitSymInfo(data);
    //获取cpu信息
    InitCpuInfo(data);
    //获取寄存器信息
    InitInstructionData(&data->main_trace);
    //写入头部信息，异常code，时间，cpu....
    WriteHeader(data);
    //枚举线程(异常线程)信息
    WriteThreadTraces(data);

    QFile log(data->file_name+".log");
    if (log.open(QIODevice::ReadWrite)) {
        log.write(data->str.toUtf8());
        log.close();
    }
}
LPTOP_LEVEL_EXCEPTION_FILTER
WINAPI
CSetUnhandledExceptionFilter(
     LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter
    )
{
    return 0;
}
//简单hook原函数使其失效
void ExceptionDump::DisableSetUnhandledExceptionFilter()
{
#if 0
    void* addr = (void*)GetProcAddress(LoadLibrary(_T("kernel32.dll")),
                                       "SetUnhandledExceptionFilter");
    if (addr) {
        uint8_t code[16];
        int size = 0;
        code[size++] = 0x33;
        code[size++] = 0xC0;//xor eax,eax
        code[size++] = 0xC2;//ret
        code[size++] = 0x04;
        code[size++] = 0x00;//ret 4

        DWORD dwOldFlag,dwTempFlag;
        VirtualProtect(addr,size,PAGE_READWRITE,&dwOldFlag);
        WriteProcessMemory(GetCurrentProcess(),addr,code,size,NULL);
        VirtualProtect(addr,size,dwOldFlag,&dwTempFlag);
    }
#endif
    if (MH_Initialize() == MH_OK) {
        MH_CreateHookApi(_T("Kernel32.dll"),
                         "SetUnhandledExceptionFilter",
                         CSetUnhandledExceptionFilter,
                         &original_);
        MH_EnableHook(MH_ALL_HOOKS);
    }
}
long ExceptionDump::ExceptionProcess(PEXCEPTION_POINTERS ExceptionInfo)
{
    QString exfile = QString::number(QDateTime::currentSecsSinceEpoch());
    exfile = QDir::toNativeSeparators(self_->path_+"/"+exfile);

    struct ExceptionHandlerData data;
    data.file_name = exfile;
    static bool inside_handler = false;

    /* don't use if a debugger is present */
    if (IsDebuggerPresent())
        return EXCEPTION_CONTINUE_SEARCH;
    if (inside_handler)
        return EXCEPTION_CONTINUE_SEARCH;

    inside_handler = true;

    HandleException(&data,ExceptionInfo);

    QString dmpfile = data.file_name+".dmp";
    HANDLE hFile = CreateFile((wchar_t*)dmpfile.utf16(),
                              GENERIC_WRITE,
                              0,
                              NULL,
                              CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL,
                              NULL);
    if (INVALID_HANDLE_VALUE != hFile ) {
        MINIDUMP_EXCEPTION_INFORMATION einfo;
        einfo.ThreadId          = GetCurrentThreadId();
        einfo.ExceptionPointers = ExceptionInfo;
        einfo.ClientPointers    = FALSE;

        data.minidump_write_dump(GetCurrentProcess(),
                                 GetCurrentProcessId(),
                                 hFile,
                                 MiniDumpNormal,
                                 &einfo,
                                 nullptr,
                                 nullptr);
        CloseHandle(hFile);
     }
    if (self_->callback_func_) {
        self_->callback_func_(userdata_);
    }
    return EXCEPTION_EXECUTE_HANDLER;//表示已经处理了异常
}

void* ExceptionDump::userdata_ = nullptr;
ExceptionDump::ExceptionDump(const QString& path, std::function<void (void*)> func, void *userdata):
    path_(path),
    callback_func_(func)
{
    SetUnhandledExceptionFilter(&ExceptionDump::ExceptionProcess);
    DisableSetUnhandledExceptionFilter();
}

void ExceptionDump::Init(const QString &path, std::function<void (void *)> func, void* userdata)
{
    if (self_) return;
    if (!QDir(path).exists()) {
        QDir().mkpath(path);
    }
    self_ = new ExceptionDump(path,func,userdata);
    userdata_ = userdata;
}
