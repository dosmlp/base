/***************************************************************************
*   Copyright (C) 2005-09 by the Quassel Project                          *
*   devel@quassel-irc.org                                                 *
*                                                                         *
*   This program is free software; you can redistribute it and/or modify  *
*   it under the terms of the GNU General Public License as published by  *
*   the Free Software Foundation; either version 2 of the License, or     *
*   (at your option) version 3.                                           *
*                                                                         *
*   This program is distributed in the hope that it will be useful,       *
*   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
*   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
*   GNU General Public License for more details.                          *
*                                                                         *
*   You should have received a copy of the GNU General Public License     *
*   along with this program; if not, write to the                         *
*   Free Software Foundation, Inc.,                                       *
*   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
***************************************************************************/

#pragma once

#include <Windows.h>
#include <DbgHelp.h>
#include <debugapi.h>
#include <TlHelp32.h>
#include <tchar.h>
#include <stdio.h>

#include <QCoreApplication>
#include <QDir>
#include <QTextStream>

namespace straceWin
{
    void loadHelpStackFrame(IMAGEHLP_STACK_FRAME&, const STACKFRAME64&);
    BOOL CALLBACK EnumSymbolsCB(PSYMBOL_INFO, ULONG, PVOID);
    BOOL CALLBACK EnumModulesCB(LPCSTR, DWORD64, PVOID);
    const QString getBacktrace();
    struct EnumModulesContext;

    QString getSourcePathAndLineNumber(HANDLE hProcess, DWORD64 addr);
    bool makeRelativePath(const QString& dir, QString& file);
}

void straceWin::loadHelpStackFrame(IMAGEHLP_STACK_FRAME& ihsf, const STACKFRAME64& stackFrame)
{
    ZeroMemory(&ihsf, sizeof(IMAGEHLP_STACK_FRAME));
    ihsf.InstructionOffset = stackFrame.AddrPC.Offset;
    ihsf.FrameOffset = stackFrame.AddrFrame.Offset;
}

BOOL CALLBACK straceWin::EnumSymbolsCB(PSYMBOL_INFO symInfo, ULONG size, PVOID user)
{
    Q_UNUSED(size)
    auto params = static_cast<QStringList *>(user);
    if (symInfo->Flags & SYMFLAG_PARAMETER)
        params->append(symInfo->Name);
    return TRUE;
}


struct straceWin::EnumModulesContext
{
    HANDLE hProcess;
    QTextStream& stream;
    EnumModulesContext(HANDLE hProcess, QTextStream& stream): hProcess(hProcess), stream(stream) {}
};

BOOL CALLBACK straceWin::EnumModulesCB(LPCSTR ModuleName, DWORD64 BaseOfDll, PVOID UserContext)
{
    Q_UNUSED(ModuleName)
    IMAGEHLP_MODULE64 mod;
    auto context = static_cast<EnumModulesContext *>(UserContext);
    mod.SizeOfStruct = sizeof(IMAGEHLP_MODULE64);
    if(SymGetModuleInfo64(context->hProcess, BaseOfDll, &mod))
    {
        QString moduleBase = QString::fromLatin1("0x%1").arg(BaseOfDll, 16, 16, QLatin1Char('0'));
        QString line = QString::fromLatin1("%1 %2 Image: %3")
                       .arg(mod.ModuleName, -25)
                       .arg(moduleBase, -13)
                       .arg(mod.LoadedImageName);
        context->stream << line << '\n';

        QString pdbName(mod.LoadedPdbName);
        if(!pdbName.isEmpty())
        {
            QString line2 = QString::fromLatin1("%1 %2")
                            .arg("", 35)
                            .arg(pdbName);
            context->stream << line2 << '\n';
        }
    }
    return TRUE;
}


/**
* Cuts off leading 'dir' path from 'file' path, otherwise leaves it unchanged
* returns true if 'dir' is an ancestor of 'file', otherwise - false
*/
bool straceWin::makeRelativePath(const QString& dir, QString& file)
{
    QString d = QDir::toNativeSeparators(QDir(dir).absolutePath());
    QString f = QDir::toNativeSeparators(QFileInfo(file).absoluteFilePath());

    // append separator at the end of dir
    QChar separator = QDir::separator();
    if (!d.isEmpty() && (d[d.length() - 1] != separator))
        d += separator;

    if (f.startsWith(d, Qt::CaseInsensitive))
    {
        f.remove(0, d.length());
        file.swap(f);

        return true;
    }

    return false;
}

QString straceWin::getSourcePathAndLineNumber(HANDLE hProcess, DWORD64 addr)
{
    IMAGEHLP_LINE64 line {};
    line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
    DWORD dwDisplacement = 0;

    if (SymGetLineFromAddr64(hProcess, addr, &dwDisplacement, &line))
    {
        QString path(line.FileName);

#if defined STACKTRACE_WIN_PROJECT_PATH || defined STACKTRACE_WIN_MAKEFILE_PATH

#define STACKTRACE_WIN_QUOTE(x)  #x
#define STACKTRACE_WIN_STRING(x)  STACKTRACE_WIN_QUOTE(x)

        //prune leading project directory path or build target directory path

        bool success = false;
#ifdef STACKTRACE_WIN_PROJECT_PATH
        QString projectPath(STACKTRACE_WIN_STRING(STACKTRACE_WIN_PROJECT_PATH));
        success = makeRelativePath(projectPath, path);
#endif

#ifdef STACKTRACE_WIN_MAKEFILE_PATH
        if (!success)
        {
            QString targetPath(STACKTRACE_WIN_STRING(STACKTRACE_WIN_MAKEFILE_PATH));
            makeRelativePath(targetPath, path);
        }
#endif
#endif
        return QString::fromLatin1("%1 : %2").arg(path).arg(line.LineNumber);
    }

    return QString();
}


#if defined( _M_IX86 ) && defined(Q_CC_MSVC)
// Disable global optimization and ignore /GS waning caused by
// inline assembly.
// not needed with mingw cause we can tell mingw which registers we use
#pragma optimize("g", off)
#pragma warning(push)
#pragma warning(disable : 4748)
#endif
const QString straceWin::getBacktrace()
{
    DWORD MachineType;
    CONTEXT Context;
    STACKFRAME64 StackFrame;

#ifdef _M_IX86
    ZeroMemory(&Context, sizeof(CONTEXT));
    Context.ContextFlags = CONTEXT_CONTROL;


    _asm
    {
        Label:
        mov [Context.Ebp], ebp;
        mov [Context.Esp], esp;
        mov eax, [Label];
        mov [Context.Eip], eax;
    }

#else
    RtlCaptureContext(&Context);
#endif

    ZeroMemory(&StackFrame, sizeof(STACKFRAME64));
#ifdef _M_IX86
    MachineType                 = IMAGE_FILE_MACHINE_I386;
    StackFrame.AddrPC.Offset    = Context.Eip;
    StackFrame.AddrPC.Mode      = AddrModeFlat;
    StackFrame.AddrFrame.Offset = Context.Ebp;
    StackFrame.AddrFrame.Mode   = AddrModeFlat;
    StackFrame.AddrStack.Offset = Context.Esp;
    StackFrame.AddrStack.Mode   = AddrModeFlat;
#elif _M_X64
    MachineType                 = IMAGE_FILE_MACHINE_AMD64;
    StackFrame.AddrPC.Offset    = Context.Rip;
    StackFrame.AddrPC.Mode      = AddrModeFlat;
    StackFrame.AddrFrame.Offset = Context.Rsp;
    StackFrame.AddrFrame.Mode   = AddrModeFlat;
    StackFrame.AddrStack.Offset = Context.Rsp;
    StackFrame.AddrStack.Mode   = AddrModeFlat;
#elif _M_IA64
    MachineType                 = IMAGE_FILE_MACHINE_IA64;
    StackFrame.AddrPC.Offset    = Context.StIIP;
    StackFrame.AddrPC.Mode      = AddrModeFlat;
    StackFrame.AddrFrame.Offset = Context.IntSp;
    StackFrame.AddrFrame.Mode   = AddrModeFlat;
    StackFrame.AddrBStore.Offset = Context.RsBSP;
    StackFrame.AddrBStore.Mode  = AddrModeFlat;
    StackFrame.AddrStack.Offset = Context.IntSp;
    StackFrame.AddrStack.Mode   = AddrModeFlat;
#else
#error "Unsupported platform"
#endif

    QString log;
    QTextStream logStream(&log);
    logStream << "```\n";

    const std::wstring appPath = _T("D:\\3rd\\git_repo\\my_projects\\driver2socks\\d2s-cli\\build\\Desktop_Qt_6_7_2_MSVC2019_64bit-Debug");//QCoreApplication::applicationDirPath().toStdWString();
    HANDLE hProcess = GetCurrentProcess();
    HANDLE hThread = GetCurrentThread();
    SymInitializeW(hProcess, appPath.c_str(), TRUE);

    DWORD64 dwDisplacement;

    ULONG64 buffer[(sizeof(SYMBOL_INFO) +
                    MAX_SYM_NAME * sizeof(TCHAR) +
                    sizeof(ULONG64) - 1) /  sizeof(ULONG64)];
    auto pSymbol = reinterpret_cast<PSYMBOL_INFO>(buffer);
    pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    pSymbol->MaxNameLen = MAX_SYM_NAME;

    IMAGEHLP_MODULE64 mod;
    mod.SizeOfStruct = sizeof(IMAGEHLP_MODULE64);

    IMAGEHLP_STACK_FRAME ihsf;
    ZeroMemory(&ihsf, sizeof(IMAGEHLP_STACK_FRAME));

    int i = 0;

    while(StackWalk64(MachineType, hProcess, hThread, &StackFrame, &Context, NULL, NULL, NULL, NULL))
    {
        if(i == 128)
            break;

        loadHelpStackFrame(ihsf, StackFrame);
        if(StackFrame.AddrPC.Offset != 0)
        { // Valid frame.

            QString fileName("???");
            if(SymGetModuleInfo64(hProcess, ihsf.InstructionOffset, &mod))
            {
                fileName = QString(mod.ImageName);
                int slashPos = fileName.lastIndexOf('\\');
                if(slashPos != -1)
                    fileName = fileName.mid(slashPos + 1);
            }
            QString funcName;
            QString sourceFile;
            if(SymFromAddr(hProcess, ihsf.InstructionOffset, &dwDisplacement, pSymbol))
            {
                funcName = QString(pSymbol->Name);

                // now ihsf.InstructionOffset points to the instruction that follows CALL instruction
                // decrease the query address by one byte to point somewhere in the CALL instruction byte sequence
                sourceFile = getSourcePathAndLineNumber(hProcess, ihsf.InstructionOffset - 1);
            }
            else
            {
                funcName = QString::fromLatin1("0x%1").arg(ihsf.InstructionOffset, 8, 16, QLatin1Char('0'));
            }
            SymSetContext(hProcess, &ihsf, NULL);
            QStringList params;
            SymEnumSymbols(hProcess, 0, NULL, EnumSymbolsCB, (PVOID)&params);

            QString insOffset = QString::fromLatin1("0x%1").arg(ihsf.InstructionOffset, 16, 16, QLatin1Char('0'));
            QString formatLine = "#%1 %2 %3 %4";
            formatLine += "(%5)";
            QString debugLine = formatLine
                                .arg(i, 3, 10)
                                .arg(fileName, -20)
                                .arg(insOffset, -11)
                                .arg(funcName)
                                .arg(params.join(", "));

            if (!sourceFile.isEmpty())
                debugLine += QString::fromLatin1("[ %1 ]").arg(sourceFile);
            logStream << debugLine << '\n';
            i++;
        }
        else
        {
            break; // we're at the end.
        }
    }

    logStream << "\n\nList of linked Modules:\n";
    EnumModulesContext modulesContext(hProcess, logStream);
    SymEnumerateModules64(hProcess, EnumModulesCB, (PVOID)&modulesContext);
    SymCleanup(hProcess);

    logStream << "```";
    return log;
}
#if defined(_M_IX86) && defined(Q_CC_MSVC)
#pragma warning(pop)
#pragma optimize("g", on)
#endif
