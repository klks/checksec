#include "pluginmain.h"
#include "plugin.h"

HINSTANCE dllInstance;
int pluginHandle;
HWND hwndDlg;
int hMenu;

PLUG_EXPORT bool pluginit(PLUG_INITSTRUCT* initStruct)
{
    return pluginInit(initStruct);
}

PLUG_EXPORT bool plugstop()
{
    return pluginStop();
}

PLUG_EXPORT void plugsetup(PLUG_SETUPSTRUCT* setupStruct)
{
    hwndDlg = setupStruct->hwndDlg;
    hMenu = setupStruct->hMenu;
    pluginSetup();
}

BOOL WINAPI DllMain(
    _In_ HINSTANCE hinstDLL,
    _In_ DWORD     fdwReason,
    _In_ LPVOID    lpvReserved
)
{
	dllInstance = hinstDLL;
    return TRUE;
}
