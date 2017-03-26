#include <Windows.h>
#include <CommCtrl.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <WinTrust.h>
#include "resource.h"
#include "plugin.h"

#pragma comment (lib, "Comctl32.lib")
#pragma comment (lib, "wintrust")

#define STATUS_YES				"Yes"
#define STATUS_NO				"No"
#define STATUS_OFF				"Off"
#define STATUS_INVALID			"Invalid"
#define STATUS_UNTRUSTED		"Untrusted"
#define STATUS_NA				"n/a"
#define STATUS_ERR				"---"

//http://www.debuginfo.com/examples/src/DebugDir.cpp
#define MakePtr( cast, ptr, addValue ) (cast)( (DWORD_PTR)(ptr) + (DWORD_PTR)(addValue))

using namespace Script;

enum
{
    MENU_CHECK,
};

enum {
	LV_MODULE,
	LV_START,
	LV_END,
	LV_SIZE,
	LV_SSEH,
	LV_DEP,
	LV_ASLR,
	LV_GS,
	LV_CFG,
	LV_SIGNED,
	LV_PATH,
	LV_ENUM_SIZE
};

//https://msdn.microsoft.com/en-us/library/windows/desktop/aa382384(v=vs.85).aspx
char * CheckSignature(char* path) {
	char *retVal = STATUS_ERR;
	LONG lStatus;
	DWORD dwLastError;

	WCHAR szPath[MAX_PATH];

	MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, path, MAX_PATH, szPath, MAX_PATH);

	WINTRUST_FILE_INFO FileData;
	memset(&FileData, 0, sizeof(FileData));
	FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
	FileData.pcwszFilePath = szPath;
	FileData.hFile = NULL;
	FileData.pgKnownSubject = NULL;

	GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	WINTRUST_DATA WinTrustData;

	memset(&WinTrustData, 0, sizeof(WinTrustData));

	WinTrustData.cbStruct = sizeof(WinTrustData);

	// Use default code signing EKU.
	WinTrustData.pPolicyCallbackData = NULL;

	// No data to pass to SIP.
	WinTrustData.pSIPClientData = NULL;

	// Disable WVT UI.
	WinTrustData.dwUIChoice = WTD_UI_NONE;

	// No revocation checking.
	WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;

	// Verify an embedded signature on a file.
	WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;

	// Verify action.
	WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;

	// Verification sets this value.
	WinTrustData.hWVTStateData = NULL;

	// Not used.
	WinTrustData.pwszURLReference = NULL;

	// This is not applicable if there is no UI because it changes 
	// the UI to accommodate running applications instead of 
	// installing applications.
	WinTrustData.dwUIContext = 0;

	// Set pFile.
	WinTrustData.pFile = &FileData;

	// WinVerifyTrust verifies signatures as specified by the GUID 
	// and Wintrust_Data.
	lStatus = WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);

	switch (lStatus)
	{
	case ERROR_SUCCESS:
		/*
		Signed file:
		- Hash that represents the subject is trusted.

		- Trusted publisher without any verification errors.

		- UI was disabled in dwUIChoice. No publisher or
		time stamp chain errors.

		- UI was enabled in dwUIChoice and the user clicked
		"Yes" when asked to install and run the signed
		subject.
		*/
		retVal = STATUS_YES;
		break;

	case TRUST_E_NOSIGNATURE:
		// The file was not signed or had a signature 
		// that was not valid.

		// Get the reason for no signature.
		dwLastError = GetLastError();
		if (TRUST_E_NOSIGNATURE == dwLastError ||
			TRUST_E_SUBJECT_FORM_UNKNOWN == dwLastError ||
			TRUST_E_PROVIDER_UNKNOWN == dwLastError)
		{
			// The file was not signed.
			retVal = STATUS_NO;
		}
		else
		{
			// The signature was not valid or there was an error 
			// opening the file.
			retVal = STATUS_INVALID;
		}

		break;

	// The hash that represents the subject or the publisher 
	// is not allowed by the admin or user.
	case TRUST_E_EXPLICIT_DISTRUST:
	// The user clicked "No" when asked to install and run.
	case TRUST_E_SUBJECT_NOT_TRUSTED:
	/*
	The hash that represents the subject or the publisher
	was not explicitly trusted by the admin and the
	admin policy has disabled user trust. No signature,
	publisher or time stamp errors.
	*/
	case CRYPT_E_SECURITY_SETTINGS:	
		retVal = STATUS_UNTRUSTED;
		break;

	default:
		// The UI was disabled in dwUIChoice or the admin policy 
		// has disabled user trust. lStatus contains the 
		// publisher or time stamp chain error.
		retVal = STATUS_ERR;
		break;
	}

	// Any hWVTStateData must be released by a call with close.
	WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;

	lStatus = WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);

	return retVal;
}

void CheckModules(HWND hDlg) {
	ListInfo *list = new ListInfo;
	Module::GetList(list);
	LVITEM lvi;
	
	HWND hListView = GetDlgItem(hDlg, IDC_LIST);
	ZeroMemory(&lvi, sizeof(lvi));
	lvi.mask = LVIF_TEXT | LVIF_PARAM;

	Module::ModuleInfo *pMI = (Module::ModuleInfo*)list->data;
	for (int i = 0; i < list->count; i++)
	{
		HANDLE hFileMap;
		HANDLE hFile;
		LPVOID lpFileBase;

		lvi.pszText = (pMI + i)->name;
		lvi.iItem = ListView_GetItemCount(hListView);
		int lvItem = ListView_InsertItem(hListView, &lvi);

		char buffer[256];

#ifdef _WIN64
		char hex_print_fmt[] = "%.16llx";
#else
		char hex_print_fmt[] = "%.8x";
#endif
		sprintf_s(buffer, hex_print_fmt, (pMI + i)->base);
		ListView_SetItemText(hListView, lvItem, LV_START, buffer);
		sprintf_s(buffer, hex_print_fmt, (pMI + i)->base + (pMI + i)->size);
		ListView_SetItemText(hListView, lvItem, LV_END, buffer);
		sprintf_s(buffer, hex_print_fmt, (pMI + i)->size);
		ListView_SetItemText(hListView, lvItem, LV_SIZE, buffer);

		//https://msdn.microsoft.com/en-us/library/ms809762.aspx
		hFile = hFile = CreateFile((pMI + i)->path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,NULL);
		if (hFile != INVALID_HANDLE_VALUE) {
			hFileMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
			if (hFileMap) {
				lpFileBase = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 0);
			}
		}

		if (!lpFileBase) {
			ListView_SetItemText(hListView, lvItem, LV_SSEH, STATUS_ERR);
			ListView_SetItemText(hListView, lvItem, LV_DEP, STATUS_ERR);
			ListView_SetItemText(hListView, lvItem, LV_ASLR, STATUS_ERR);
			ListView_SetItemText(hListView, lvItem, LV_GS, STATUS_ERR);
			ListView_SetItemText(hListView, lvItem, LV_CFG, STATUS_ERR);
			ListView_SetItemText(hListView, lvItem, LV_SIGNED, STATUS_ERR);
		}
		else {

			char *has_ASLR = STATUS_ERR;
			char *has_SAFESEH = STATUS_ERR;
			char *has_DEP = STATUS_ERR;
			char *has_GS = STATUS_ERR;
			char *has_CFG = STATUS_ERR;

			PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)lpFileBase;

			if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE) {
				PIMAGE_NT_HEADERS pNTHeader = MakePtr(PIMAGE_NT_HEADERS, dosHeader, dosHeader->e_lfanew);
				if (pNTHeader->Signature == IMAGE_NT_SIGNATURE) {
					PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)&pNTHeader->FileHeader;

					WORD DllCharacteristics;
					if (pFileHeader->Machine == IMAGE_FILE_MACHINE_I386) {
						PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)&pNTHeader->OptionalHeader;
						DllCharacteristics = pOptionalHeader->DllCharacteristics;
					}
					else {
						PIMAGE_OPTIONAL_HEADER64 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER64)&pNTHeader->OptionalHeader;
						DllCharacteristics = pOptionalHeader->DllCharacteristics;
					}

					if (DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) has_ASLR = STATUS_YES;
					else has_ASLR = STATUS_NO;

					if (DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) has_DEP = STATUS_YES;
					else has_DEP = STATUS_NO;

					if (DllCharacteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF) has_CFG = STATUS_YES;
					else has_CFG = STATUS_NO;

					if (DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH) {
						has_SAFESEH = STATUS_NO;
					}

					PIMAGE_DATA_DIRECTORY pConfigDataDirectory = &pNTHeader->OptionalHeader.DataDirectory[10];
					if (pConfigDataDirectory->VirtualAddress != 0) {
						if (pFileHeader->Machine == IMAGE_FILE_MACHINE_I386) {
							PIMAGE_LOAD_CONFIG_DIRECTORY32 pLoadConfig = MakePtr(PIMAGE_LOAD_CONFIG_DIRECTORY32, dosHeader, pConfigDataDirectory->VirtualAddress);

							if (pLoadConfig->SecurityCookie != 0) has_GS = STATUS_YES;
							else has_GS = STATUS_NO;

							if (strcmp(has_SAFESEH, STATUS_ERR) == 0) {
								if (pLoadConfig->SEHandlerTable != 0) has_SAFESEH = STATUS_YES;
								else has_SAFESEH = STATUS_OFF;
							}
						}
						else {
							PIMAGE_LOAD_CONFIG_DIRECTORY64 pLoadConfig = MakePtr(PIMAGE_LOAD_CONFIG_DIRECTORY64, dosHeader, pConfigDataDirectory->VirtualAddress);

							if (pLoadConfig->SecurityCookie != 0) has_GS = STATUS_YES;
							else has_GS = STATUS_NO;

							//Not applicable for 64bit
							has_SAFESEH = STATUS_NA;
						}
					}
					else {
						if (pFileHeader->Machine == IMAGE_FILE_MACHINE_I386) has_SAFESEH = STATUS_ERR;
						else has_SAFESEH = STATUS_NA;	//Not applicable for 64bit

						has_GS = STATUS_ERR;
					}
				}
			}

			ListView_SetItemText(hListView, lvItem, LV_SSEH, has_SAFESEH);
			ListView_SetItemText(hListView, lvItem, LV_DEP, has_DEP);
			ListView_SetItemText(hListView, lvItem, LV_ASLR, has_ASLR);
			ListView_SetItemText(hListView, lvItem, LV_GS, has_GS);
			ListView_SetItemText(hListView, lvItem, LV_CFG, has_CFG);
			
		}
		ListView_SetItemText(hListView, lvItem, LV_SIGNED, CheckSignature((pMI + i)->path));
		ListView_SetItemText(hListView, lvItem, LV_PATH, (pMI + i)->path);

		if (lpFileBase) UnmapViewOfFile(lpFileBase);
		if (hFileMap) CloseHandle(hFileMap);
		if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
	}

	for (int i = 0; i < LV_ENUM_SIZE; i++) {
		if (i == LV_SSEH || i == LV_DEP || i == LV_ASLR ||
			i == LV_GS || i== LV_CFG || i == LV_SIGNED) {
			ListView_SetColumnWidth(hListView, i, -2);
		}
		else {
			ListView_SetColumnWidth(hListView, i, -1);
		}
	}
	free(list);
}

LRESULT CustomDraw(HWND hDlg, LPARAM lParam) {
	LPNMLVCUSTOMDRAW lplvcd = (LPNMLVCUSTOMDRAW)lParam;
	char cBuffer[10];

	switch (lplvcd->nmcd.dwDrawStage)
	{
	case CDDS_PREPAINT:
		return CDRF_NOTIFYITEMDRAW;

	case CDDS_ITEMPREPAINT:
		return CDRF_NOTIFYSUBITEMDRAW;

	case CDDS_SUBITEM | CDDS_ITEMPREPAINT:
		lplvcd->clrTextBk = RGB(0xff, 0xf8, 0xf0);

		switch (lplvcd->iSubItem)
		{
		case LV_SSEH:
		case LV_DEP:
		case LV_ASLR:
		case LV_GS:
		case LV_CFG:
		case LV_SIGNED:
			ListView_GetItemText(GetDlgItem(hDlg, IDC_LIST), lplvcd->nmcd.dwItemSpec, lplvcd->iSubItem, cBuffer, sizeof(cBuffer));
			if (strcmp(cBuffer, STATUS_NO) == 0 || strcmp(cBuffer, STATUS_OFF) == 0 || 
				strcmp(cBuffer, STATUS_INVALID) == 0 || strcmp(cBuffer, STATUS_INVALID) == 0){
				lplvcd->clrText = RGB(0xff, 0x00, 0x0);
			}
			else {
				lplvcd->clrText = RGB(0x00, 0x00, 0x0);
			}
			break;
		default:
			lplvcd->clrText = RGB(0x00, 0x00, 0x0);
			break;
		}
		return CDRF_NEWFONT;
	}

	return CDRF_DODEFAULT;
}

void SetupListview(HWND hDlg) {
	LVCOLUMN lvc = { 0 };
	lvc.cx = 100;

	HWND hListView = GetDlgItem(hDlg, IDC_LIST);

	lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	lvc.pszText = "Module";
	ListView_InsertColumn(hListView, LV_MODULE, &lvc);

	lvc.pszText = "Start";
	ListView_InsertColumn(hListView, LV_START, &lvc);

	lvc.pszText = "End";
	ListView_InsertColumn(hListView, LV_END, &lvc);

	lvc.pszText = "Size";
	ListView_InsertColumn(hListView, LV_SIZE, &lvc);

	lvc.pszText = "SafeSEH";
	ListView_InsertColumn(hListView, LV_SSEH, &lvc);

	lvc.pszText = "DEP";
	ListView_InsertColumn(hListView, LV_DEP, &lvc);

	lvc.pszText = "ASLR";
	ListView_InsertColumn(hListView, LV_ASLR, &lvc);

	lvc.pszText = "/GS";
	ListView_InsertColumn(hListView, LV_GS, &lvc);

	lvc.pszText = "CFG";
	ListView_InsertColumn(hListView, LV_CFG, &lvc);

	lvc.pszText = "Signed";
	ListView_InsertColumn(hListView, LV_SIGNED, &lvc);

	lvc.pszText = "Path";
	ListView_InsertColumn(hListView, LV_PATH, &lvc);

	ListView_SetExtendedListViewStyle(hListView, LVS_EX_FULLROWSELECT);
	ListView_SetBkColor(hListView, RGB(0xff, 0xf8, 0xf0));
}

INT_PTR CALLBACK DialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	RECT r;

	switch (uMsg)
	{
	case WM_CLOSE:
		EndDialog(hDlg, wParam);
		break;

	case WM_PAINT:
		return FALSE;

	case WM_NOTIFY:
		switch (LOWORD(wParam)) {
		case IDC_LIST:
			LPNMLISTVIEW pnm = (LPNMLISTVIEW)lParam;

			if (pnm->hdr.hwndFrom == GetDlgItem(hDlg, IDC_LIST) && pnm->hdr.code == NM_CUSTOMDRAW) {
				SetWindowLongPtr(hDlg, DWLP_MSGRESULT, (LONG)CustomDraw(hDlg, lParam));
				return TRUE;
			}
			break;
		}
		break;

	case WM_SIZE:	
		GetClientRect(hDlg, &r);
		SetWindowPos(GetDlgItem(hDlg, IDC_LIST), NULL, 0, 0, r.right, r.bottom, SWP_NOMOVE | SWP_NOZORDER);
		break;

	case WM_INITDIALOG:	
		SetupListview(hDlg);
		CheckModules(hDlg);
		break;

	default:
		return FALSE;
	}
	return TRUE;
}

PLUG_EXPORT void CBMENUENTRY(CBTYPE cbType, PLUG_CB_MENUENTRY* info)
{
    switch(info->hEntry)
    {
    case MENU_CHECK:
		DialogBox(dllInstance, MAKEINTRESOURCE(IDD_DLGCHKSEC), hwndDlg, (DLGPROC)DialogProc);
        break;

    default:
        break;
    }
}

//Initialize your plugin data here.
bool pluginInit(PLUG_INITSTRUCT* initStruct)
{
	initStruct->pluginVersion = PLUGIN_VERSION;
	initStruct->sdkVersion = PLUG_SDKVERSION;
	strncpy_s(initStruct->pluginName, PLUGIN_NAME, _TRUNCATE);
	pluginHandle = initStruct->pluginHandle;

	CoInitialize(NULL);
	INITCOMMONCONTROLSEX icex;           // Structure for control initialization.
	icex.dwICC = ICC_LISTVIEW_CLASSES;
	InitCommonControlsEx(&icex);

    return true; //Return false to cancel loading the plugin.
}

//Deinitialize your plugin data here (clearing menus optional).
bool pluginStop()
{
    _plugin_unregistercommand(pluginHandle, PLUGIN_NAME);
    _plugin_menuclear(hMenu);
    return true;
}

//Do GUI/Menu related things here.
void pluginSetup()
{
    _plugin_menuaddentry(hMenu, MENU_CHECK, "&Check");
}
