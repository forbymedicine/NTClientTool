#include <windows.h>
#include <stdio.h>
#include <utils.h>
#include "minhook.h"
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "cryptui.lib")
typedef PCCERT_CONTEXT(WINAPI* CryptUIDlgSelectCertificateFromStore_t)(
	HCERTSTORE hCertStore,
	HWND hwnd,
	PCWSTR pwszTitle,
	PCWSTR pwszDisplayString,
	DWORD dwDontUseColumn,
	DWORD dwFlags,
	void* pvReserved
	);
HMODULE g_hModule = NULL;
CryptUIDlgSelectCertificateFromStore_t OriginalCryptUIDlgSelectCertificateFromStore = NULL;
PCCERT_CONTEXT WINAPI HookedCryptUIDlgSelectCertificateFromStore(
	HCERTSTORE hCertStore,
	HWND hwnd,
	PCWSTR pwszTitle,
	PCWSTR pwszDisplayString,
	DWORD dwDontUseColumn,
	DWORD dwFlags,
	void* pvReserved
) {
	int my_cert_count = 0;
	readMyCerificates(0, &my_cert_count);
	if (my_cert_count == 0) {
		return OriginalCryptUIDlgSelectCertificateFromStore(hCertStore, hwnd, pwszTitle, pwszDisplayString, dwDontUseColumn, dwFlags, pvReserved);
	}
	if (my_cert_count == 1) {
		HCERTSTORE hMyStore = CertOpenSystemStoreW(0, L"MY");
		if (!hMyStore) {
			return OriginalCryptUIDlgSelectCertificateFromStore(hCertStore, hwnd, pwszTitle, pwszDisplayString, dwDontUseColumn, dwFlags, pvReserved);
		}
		PCCERT_CONTEXT pFirstCert = CertEnumCertificatesInStore(hMyStore, NULL);
		if (!pFirstCert) {
			CertCloseStore(hMyStore, 0);
			return OriginalCryptUIDlgSelectCertificateFromStore(hCertStore, hwnd, pwszTitle, pwszDisplayString, dwDontUseColumn, dwFlags, pvReserved);
		}
		PCCERT_CONTEXT pResult = CertDuplicateCertificateContext(pFirstCert);
		CertFreeCertificateContext(pFirstCert);
		CertCloseStore(hMyStore, 0);
		return pResult;
	}
	int plugged_usb_count = 0;
	getPluggedUSBSerialNumbers(0, &plugged_usb_count);
	if (plugged_usb_count != 1) {
		return OriginalCryptUIDlgSelectCertificateFromStore(hCertStore, hwnd, pwszTitle, pwszDisplayString, dwDontUseColumn, dwFlags, pvReserved);
	}
	PCertData plugged = calloc(1, sizeof(CertData));
	if (plugged == NULL) {
		return OriginalCryptUIDlgSelectCertificateFromStore(hCertStore, hwnd, pwszTitle, pwszDisplayString, dwDontUseColumn, dwFlags, pvReserved);
	}
	getPluggedUSBSerialNumbers(plugged, &plugged_usb_count);
	PCertData certData = 0;
	if (plugged_usb_count == 1) {
		certData = findSavedCertDataByUSBSerial(plugged->USBSerial);
	}
	free(plugged);
	if (certData == NULL) {
		return OriginalCryptUIDlgSelectCertificateFromStore(hCertStore, hwnd, pwszTitle, pwszDisplayString, dwDontUseColumn, dwFlags, pvReserved);
	}
	PCCERT_CONTEXT pResult = findCertContext(certData->ContainerName, certData->Serial);
	free(certData);
	if (pResult == NULL) {
		return OriginalCryptUIDlgSelectCertificateFromStore(hCertStore, hwnd, pwszTitle, pwszDisplayString, dwDontUseColumn, dwFlags, pvReserved);
	}
	return pResult;
}
DWORD WINAPI MainThread(void* data) {
	if (MH_Initialize() != MH_OK) {
		MessageBoxA(0, "Failed to initialize MinHook", "Minhook", 0);
		return FALSE;
	}
	HMODULE hCryptUI = GetModuleHandleW(L"CryptUI.dll");
	if (!hCryptUI) {
		MessageBoxA(0, "Failed to get CryptUI.dll handle", "Minhook", 0);
		return FALSE;
	}

	FARPROC pTargetFunc = GetProcAddress(hCryptUI, "CryptUIDlgSelectCertificateFromStore");
	if (!pTargetFunc) {
		MessageBoxA(0, "Failed to get CryptUIDlgSelectCertificateFromStore address", "Minhook", 0);
		return FALSE;
	}

	MH_STATUS status = MH_CreateHook(
		pTargetFunc,
		&HookedCryptUIDlgSelectCertificateFromStore,
		(void*)(&OriginalCryptUIDlgSelectCertificateFromStore)
	);

	if (status != MH_OK) {
		MessageBoxA(0, "Failed to create hook", "Minhook", 0);
		return FALSE;
	}
	status = MH_EnableHook(pTargetFunc);
	if (status != MH_OK) {
		MessageBoxA(0, "Failed to enable hook", "Minhook", 0);
		return FALSE;
	}
	DWORD pid = GetProcessIdByName(L"NTClientTool.exe");
	if (pid != 0)
	{
		HANDLE hProcess = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_INFORMATION, FALSE, pid);
		if (hProcess != 0) {
			DWORD waitResult = WaitForSingleObject(hProcess, INFINITE);
			CloseHandle(hProcess);
			MH_DisableHook(MH_ALL_HOOKS);
			MH_Uninitialize();
			if (g_hModule != 0) {
				DWORD exit;
				FreeLibraryAndExitThread(g_hModule, &exit);
				return exit;
			}
		}
	}
	return 0;
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
	if (reason == DLL_PROCESS_ATTACH) {
		g_hModule = hModule;
		HANDLE h = CreateThread(NULL, 0, MainThread, NULL, 0, NULL);
		DisableThreadLibraryCalls(hModule);
		if (h > 0) {
			CloseHandle(h);
		}		
	}

	return TRUE;
}