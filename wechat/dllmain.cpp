#include <windows.h>
#include "anti_revoke.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        InstallRevokeHook();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

extern "C"{

__declspec(dllexport) HRESULT D3D11CreateDevice(
    void* pAdapter,
    size_t DriverType,
    HMODULE Software,
    UINT Flags,
    const void* pFeatureLevels,
    UINT FeatureLevels,
    UINT SDKVersion,
    void** ppDevice,
    void* pFeatureLevel,
    void** ppImmediateContext)
{
    wchar_t path[MAX_PATH] = {};
    GetSystemDirectory(path, MAX_PATH);
    wcscat_s(path, L"\\");
    wcscat_s(path, L"d3d11.dll");
    auto m = LoadLibrary(path);

    auto x = (decltype(&D3D11CreateDevice))GetProcAddress(m, "D3D11CreateDevice");

    return x(pAdapter, DriverType, Software, Flags, pFeatureLevels, FeatureLevels, SDKVersion, ppDevice, pFeatureLevel, ppImmediateContext);
}

}