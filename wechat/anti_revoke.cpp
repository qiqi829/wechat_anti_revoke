#include <time.h>
#include <windows.h>
#include <intrin.h>
#include <string>
#include "anti_revoke.h"
#include "detours/detours.h"

#define LOG_INFO(msg) OutputDebugString(msg)

decltype(&GetCurrentThreadId) WinGetCurrentThreadId = GetCurrentThreadId;

size_t WeChatWinModuleBegin = 0;
size_t WeChatWinModuleCodePageEnd = 0;
size_t WeChatWinModuleEnd = 0;

void ReplaceString(wchar_t * buffer, const wchar_t* src, const wchar_t* dst)
{
    //assert(wcslen(src) == wcslen(dst));

    auto ptr = wcsstr(buffer, src);
    if (ptr == nullptr)
    {
        return;
    }

    memcpy(ptr, dst, wcslen(dst) * 2);
}

std::wstring CreateUniqueMessageId(size_t len /*19*/)
{
    static size_t uniqueID = 1000;

    std::wstring serverMsgId;
    serverMsgId.reserve(30);

    serverMsgId += std::to_wstring(time(0) % 10000000);                 // len 7
    serverMsgId += std::to_wstring(WinGetCurrentThreadId() % 1000);     // len 3
    serverMsgId += std::to_wstring(uniqueID++);                         // len 4
    serverMsgId += std::to_wstring(99999999 + GetTickCount64() * GetCurrentProcessId());

    return serverMsgId.substr(0, len);
}

//<sysmsg type="revokemsg">
//    <revokemsg>
//        <session>*********@chatroom</session>
//        <msgid>136*******</msgid>
//        <newmsgid>920*************</newmsgid>
//        <replacemsg><![CDATA["****" 撤回了一条消息]]></replacemsg>
//    </revokemsg>
//</sysmsg>
wchar_t* SafeGetObjectXmlMember(size_t object)
{
    const wchar_t* xmlHeader = LR"(<sysmsg type="revokemsg">)";
    for (size_t memberOffset = 0x80; memberOffset < 0xA0; memberOffset += 8)    // ver:3.9.12.37 = 0x88
    {
        __try
        {
            auto xml = *(wchar_t**)(object + memberOffset);
            if (xml[0] != L'<' || xml[1] != L's')
            {
                continue;
            }

            if (_wcsnicmp(xml, xmlHeader, wcslen(xmlHeader)) == 0)  // cannot try catch
            {
                return xml;
            }
        }
        __except(1) {}
    }
    return nullptr;
}

void ModifyXmlString(size_t object)
{
    wchar_t* xmlString = SafeGetObjectXmlMember(object);
    if (xmlString == nullptr)
    {
        return;
    }

    LOG_INFO(xmlString);

    // revoke by self ?
    if (wcsstr(xmlString, L"[你撤回了一条消息]") != 0)
    {
        return;
    }

    ReplaceString(xmlString, L"撤回了一条消息", L"撤回了一个寂寞");

    // 1. delete "newmsgid" tag, nothing to replace
    //{
    //    ReplaceString(xmlString, L"<newmsgid>", L"<oldmsgid>");
    //    ReplaceString(xmlString, L"</newmsgid>", L"</oldmsgid>");
    //}

    // 2. create another msg id, keep target msg and revoke msg
    {
        auto msgidBegin = wcsstr(xmlString, L"<newmsgid>") + wcslen(L"<newmsgid>");
        auto msgidEnd = wcsstr(xmlString, L"</newmsgid>");

        size_t msgidLen = msgidEnd - msgidBegin; 

        std::wstring serverId = CreateUniqueMessageId(msgidLen);

        LOG_INFO(L"local created server id:");
        LOG_INFO(serverId.c_str());

        memcpy(msgidBegin, serverId.c_str(), serverId.size() * 2);
    }
}

DWORD WINAPI MyGetCurrentThreadId(size_t msgType, size_t rdx, size_t r8 /*this*/)
{
    auto currentThreadId = WinGetCurrentThreadId();

    size_t retAddress = (size_t)_ReturnAddress();
    if (retAddress < WeChatWinModuleBegin || retAddress > WeChatWinModuleCodePageEnd)
    {
        return currentThreadId;
    }

    size_t vtable = 0;
    ReadProcessMemory(GetCurrentProcess(), (void*)r8, &vtable, sizeof(vtable), 0);
    if (vtable < WeChatWinModuleCodePageEnd || WeChatWinModuleCodePageEnd > WeChatWinModuleEnd)
    {
        return currentThreadId; 
    }

    //if (0) // 
    //{
    //    <catalog name="basecontrol">
    //        <functioncontrol type="wxservice.exe">
    //            <switch 
    //                cfgver="1"
    //                rootswitch="1"
    //                md5filelimit="102400"
    //                ldrhook="1"
    //        ...
    //        <excludereportfilelist>
    //        <item name="b.dll"/>
    //        </excludereportfilelist>
    //        <excludereportsignnerlist>
    //        <item signner="Microsoft Windows"/>
    //        </excludereportsignnerlist>
    //        <specialprocrule>
    //        <item name="wechat.exe"/>
    //        <item name="wechatweb.exe"/>
    //        <item name="wxservice.exe"/>
    //}

    if (msgType == 4 /* revoke */)
    {
        ModifyXmlString(r8);
    }

    return currentThreadId;
}

bool InstallRevokeHook()
{
    {
        size_t moduleImageBase = (size_t)GetModuleHandle(L"wechatwin.dll");
        if (moduleImageBase == 0)
        {
            return false;
        }

        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleImageBase;
        PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(moduleImageBase + dosHeader->e_lfanew);

        WeChatWinModuleBegin = moduleImageBase;
        WeChatWinModuleCodePageEnd = WeChatWinModuleBegin + ntHeader->OptionalHeader.SizeOfCode + ntHeader->OptionalHeader.BaseOfCode;
        WeChatWinModuleEnd = WeChatWinModuleBegin + ntHeader->OptionalHeader.SizeOfImage;
    }

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetourAttach(&(PVOID&)WinGetCurrentThreadId, MyGetCurrentThreadId);

    DetourTransactionCommit();

    return true;
}
