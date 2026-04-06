#define _CRT_SECURE_NO_WARNINGS
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


HWND g_checkBox;
HWND g_passwordEdit = NULL;
HWND g_avest_window = NULL;
HWND g_containerNameEdit = NULL;
HWND g_usbSerialCombobox = NULL;
HWND g_okButton = NULL;
WNDPROC g_originalButtonProc = NULL;
volatile BOOL g_hookRunning = FALSE;

LRESULT CALLBACK OkButtonHook(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
	TCHAR password[64] = { 0 };
	TCHAR usbSerial[128] = { 0 };
	TCHAR containerName[256] = { 0 };
	LRESULT res;
	if (msg == WM_LBUTTONDOWN && g_checkBox != 0 && SendMessage(g_checkBox, BM_GETCHECK, 0, 0) == BST_CHECKED) {
		res = SendMessage(g_passwordEdit, WM_GETTEXT, 64, (LPARAM)password);
		if (g_usbSerialCombobox != NULL && g_passwordEdit != NULL) {
			SendMessage(g_usbSerialCombobox, WM_GETTEXT, 128, (LPARAM)usbSerial);
			SendMessage(g_containerNameEdit, WM_GETTEXT, 256, (LPARAM)containerName);
			size_t usbSerial_len = wcsnlen_s(usbSerial, sizeof(usbSerial));
			size_t containerName_len = wcsnlen_s(containerName, sizeof(containerName));
			size_t password_len = wcsnlen_s(containerName, sizeof(containerName));
			if (usbSerial_len > 1 && containerName_len > 1 && password_len > 1) {
				int cert_count = 0;
				PCertData certs;
				int err = ReadSavedFile(&certs, &cert_count);
				PCertData certData = NULL;
				if (cert_count > 0) {
					certData = findCertDataByUSBSerialAndContainerName(certs, cert_count, usbSerial, containerName);
					if (certData != NULL) {
						memcpy(certData->password, password, password_len * sizeof(TCHAR));
						WriteSavedFile(certs, cert_count);
					}
					free(certs);
				}
			}
		}
	}
	return CallWindowProc(g_originalButtonProc, hWnd, msg, wParam, lParam);
}

void CALLBACK WinEventProc(
	HWINEVENTHOOK hWinEventHook,
	DWORD event,
	HWND hwnd,
	LONG idObject,
	LONG idChild,
	DWORD dwEventThread,
	DWORD dwmsEventTime)
{
	DWORD windowProcessId = 0;
	wchar_t windowTitle[256];
	GetWindowTextW(hwnd, windowTitle, 256);

	GetWindowThreadProcessId(hwnd, &windowProcessId);
	if (windowProcessId != GetCurrentProcessId()) {
		return;
	}
	wchar_t className[256];
	GetClassNameW(hwnd, className, sizeof(className) / sizeof(wchar_t));
	if ((wcsstr(windowTitle, AVEST_TITLE_1) != NULL || wcsstr(windowTitle, AVEST_TITLE_2) != NULL) && IsWindowVisible(hwnd) && (event == EVENT_OBJECT_SHOW || event == EVENT_OBJECT_FOCUS)) {
		HWND firstEdit = NULL;
		TCHAR className[256] = { 0 };
		TCHAR windowText[256] = { 0 };
		TCHAR containerName[256] = { 0 };
		HWND hChild = GetWindow(hwnd, GW_CHILD);
		HWND passwordArea = NULL;
		while (hChild != NULL) {
			GetClassName(hChild, className, 256);
			if (wcsstr(className, L"Button") != NULL) {
				GetWindowText(hChild, windowText, 256);
				if (wcsstr(windowText, L"OK") != NULL) {
					g_okButton = hChild;
				}
				else if (wcsstr(windowText, L"Пароль") != NULL) {
					EnableWindow(hChild, FALSE);
					passwordArea = hChild;
				}
			}
			else if (wcsstr(className, L"ComboBox") != NULL) {
				g_usbSerialCombobox = hChild;
			}
			else if (wcsstr(className, L"Edit") != NULL) {
				if (firstEdit == NULL) {
					firstEdit = hChild;
				}
				else {
					LRESULT res = SendMessage(hChild, WM_GETTEXT, 256, (LPARAM)windowText);
					if (IsWindowVisible(hChild)) {
						if (res != 0) {
							if (wcsnlen_s(windowText, sizeof(windowText)) > 12) {
								g_containerNameEdit = hChild;
								memcpy(containerName, windowText, sizeof(containerName));
							}
						}
					}
				}
			}
			if (g_passwordEdit == NULL) {
				g_passwordEdit = firstEdit;
			}
			//RECT rect;
			//GetWindowRect(hChild, &rect);
			//printf("HWND: %p\n", hChild);
			//printf("   Class: %S\n", className);
			//printf("   Text: %S\n", windowText);
			//printf("   Rect: (%d,%d)-(%d,%d)\n",
			//	rect.left, rect.top, rect.right, rect.bottom);
			//printf("\n");

			hChild = GetWindow(hChild, GW_HWNDNEXT);
		}
		if (g_okButton != NULL) {
			if (g_avest_window != hwnd) {
				if (passwordArea == NULL) {
					g_checkBox = CreateWindowA("BUTTON", "Сохранить", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 335, 215, 75, 23, hwnd, (HMENU)885, GetModuleHandle(NULL), NULL);
				}
				else {
					g_checkBox = CreateWindowA("BUTTON", "Сохранить пароль", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 26, 244, 280, 23, hwnd, (HMENU)885, GetModuleHandle(NULL), NULL);
				}
				if (g_checkBox) {
					SendMessage(g_checkBox, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);
					SendMessage(g_checkBox, BM_SETCHECK, BST_UNCHECKED, 0);
					g_originalButtonProc = (WNDPROC)SetWindowLongPtr(g_okButton, GWLP_WNDPROC, (LONG_PTR)OkButtonHook);
				}
				g_avest_window = hwnd;
			}
		}
	}
}
DWORD WINAPI HookThread(void* data) {
	HWINEVENTHOOK g_hHook = SetWinEventHook(
		EVENT_OBJECT_SHOW,
		EVENT_OBJECT_FOCUS,
		NULL,
		WinEventProc,
		GetCurrentProcessId(),
		0,
		WINEVENT_OUTOFCONTEXT
	);
	g_hookRunning = TRUE;
	while (g_hookRunning) {
		MSG msg;
		while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
			if (msg.message == WM_QUIT) {
				g_hookRunning = FALSE;
				break;
			}
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
		if (g_avest_window) {
			if (!IsWindow(g_avest_window)) {
				g_checkBox = NULL;
				g_passwordEdit = NULL;
				g_avest_window = NULL;
				g_containerNameEdit = NULL;
				g_usbSerialCombobox = NULL;
				g_okButton = NULL;
			}
			fflush(stdout);
		}
		Sleep(50);
	}
	if (g_avest_window && IsWindow(g_avest_window) && g_originalButtonProc) {
		if (IsWindow(g_checkBox)) {
			DestroyWindow(g_checkBox);
		}
		(WNDPROC)SetWindowLongPtr(g_okButton, GWLP_WNDPROC, (LONG_PTR)g_originalButtonProc);
		fflush(stdout);
	}
	//MSG msg;
	//BOOL result;
	//while ((result = GetMessage(&msg, NULL, 0, 0)) != 0) {
	//	if (result == -1) {
	//		DWORD error = GetLastError();
	//		wprintf(L"Hook error %lu\n", error);
	//		break;
	//	}
	//	TranslateMessage(&msg);
	//	DispatchMessage(&msg);
	//}
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

	HANDLE hThread = CreateThread(NULL, 0, HookThread, NULL, 0, NULL);
	DWORD pid = GetProcessIdByName(L"NTClientTool.exe");
	if (pid != 0)
	{
		HANDLE hProcess = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_INFORMATION, FALSE, pid);
		if (hProcess != 0) {
			DWORD waitResult = WaitForSingleObject(hProcess, INFINITE);
			CloseHandle(hProcess);
			MH_DisableHook(MH_ALL_HOOKS);
			MH_Uninitialize();
			g_hookRunning = FALSE;
			if (hThread != 0) {
				WaitForSingleObject(hThread, INFINITE);
				CloseHandle(hThread);
			}
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