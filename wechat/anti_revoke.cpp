#include <time.h>
#include <windows.h>
#include <intrin.h>
#include <string>
#include "anti_revoke.h"
#include "detours/detours.h"

size_t g_ProcessNewXMLMsgProc = 0;

std::string CreateUniqueMessageId(size_t len /*19*/)
{
    static size_t uniqueID = 1000;

    std::string serverMsgId;
    serverMsgId.reserve(30);

    serverMsgId += std::to_string(time(0) % 10000000);                 // len 7
    serverMsgId += std::to_string(GetCurrentThreadId() % 1000);        // len 3
    serverMsgId += std::to_string(uniqueID++);                         // len 4
    serverMsgId += std::to_string(99999999 + GetTickCount64() * GetCurrentProcessId());

    return serverMsgId.substr(0, len);
}

size_t MyProcessNewXMLMsg(size_t a1, size_t a2)
{
    size_t v1 = *(size_t*)(a2 + 0x20);
    if (v1 != 0) 
    {
        size_t v2 = *(size_t*)(v1 + 0x8);
        char* xml = *(char**)v2;

        OutputDebugStringA(xml);

        const char* revokeHeader = R"(<sysmsg type="revokemsg">)";
        if(strstr(xml, revokeHeader) != 0)
        {
            auto msgidBegin = strstr(xml, "<newmsgid>") + strlen("<newmsgid>");
            auto msgidEnd = strstr(xml, "</newmsgid>");

            size_t msgidLen = msgidEnd - msgidBegin; 

            std::string serverId = CreateUniqueMessageId(msgidLen);

            memcpy(msgidBegin, serverId.c_str(), serverId.size());
        }
    }

    return ((decltype(&MyProcessNewXMLMsg))g_ProcessNewXMLMsgProc)(a1, a2);
}

size_t FindProcessNewXMLMsg()
{
    size_t moduleImageBase = (size_t)GetModuleHandle(L"Weixin.dll");
    if (moduleImageBase == 0)
    {
        return 0;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleImageBase;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(moduleImageBase + dosHeader->e_lfanew);

    size_t weChatWinModuleBegin = moduleImageBase;
    size_t weChatWinModuleEnd = weChatWinModuleBegin + ntHeader->OptionalHeader.SizeOfImage;
    size_t weChatWinModuleCodePageEnd = weChatWinModuleBegin + ntHeader->OptionalHeader.SizeOfCode + ntHeader->OptionalHeader.BaseOfCode;

    const char* hookProcName = "ProcessNewXMLMsg";

    // 1: 在.radata找到字符串 ProcessNewXMLMsg
    // .rdata:00007FFA594370F0 50 72 6F 63 65 73 73 4E 65 77 58+  xmmword_7FFA594370F0 xmmword 67734D4C4D5877654E737365636F7250h
    size_t xmmProcessNewXMLMsg = 0;
    size_t procNameLength = strlen(hookProcName);
    const char* ptr = (const char*)(weChatWinModuleCodePageEnd);
    for (size_t i = 0; i < weChatWinModuleEnd - weChatWinModuleCodePageEnd - 100; i++)
    {
        if (ptr[i] == 'P' && memcmp(ptr + i, hookProcName, procNameLength) == 0) {
            xmmProcessNewXMLMsg = weChatWinModuleCodePageEnd + i;
            break;
        }
    }
    if (xmmProcessNewXMLMsg == 0) {
        return 0;
    }

    xmmProcessNewXMLMsg -= 7; // len of [movaps]

    // 2：在.code找引用 
    // .text:00007FFA541C5679 0F 28 05 70 1A 27 05  movaps  xmm0, cs:xmmword_7FFA594370F0
    const unsigned char* MovapsCodeAddress = 0;
    const unsigned char* pcode = (const unsigned char*)weChatWinModuleBegin + 0x1000;
    for (size_t i = 0; i < ntHeader->OptionalHeader.SizeOfCode; i++, pcode++)
    {
        if (*pcode == 0x0f && pcode[1] == 0x28) {
            if (((size_t)pcode + *(DWORD*)(pcode + 3)) == xmmProcessNewXMLMsg) {
                MovapsCodeAddress = pcode;
                break;
            }
        }
    }
    if (MovapsCodeAddress == 0) {
        return 0;
    }

    // 3：往上翻函数头
    size_t ProcessNewXMLMsg = 0;
    size_t functionBeginAddress = (size_t)MovapsCodeAddress;
    functionBeginAddress = functionBeginAddress & (~0xf);
    for (size_t i = 0; i < 200; i++)
    {
        if (*(size_t*)functionBeginAddress == 0xcccccccccccccccc) {
            ProcessNewXMLMsg = functionBeginAddress + 8;
            break;
        }
        functionBeginAddress -= 8;
    }

    return ProcessNewXMLMsg;
}

bool InstallRevokeHook()
{
    size_t ProcessNewXMLMsg = FindProcessNewXMLMsg();
    if(ProcessNewXMLMsg == 0)
    {
        MessageBox(0, L"error, pls delete me", 0, 0);
        return false;
    }

    g_ProcessNewXMLMsgProc = ProcessNewXMLMsg;

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetourAttach(&(PVOID&)g_ProcessNewXMLMsgProc, MyProcessNewXMLMsg);

    DetourTransactionCommit();

    return true;
}
