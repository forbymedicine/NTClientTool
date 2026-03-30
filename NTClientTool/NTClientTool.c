#include <utils.h>
#include <windows.h>
#include <stdio.h>
#include <stdbool.h>
#include <locale.h>
#include <psapi.h>
#pragma comment(lib, "user32.lib")

#define MAX_LINE_LEN 512
#define MAX_PATH_LEN 260

#define WINDOWS_TITLE_1 L"\u0411\u0435\u0437\u043e\u043f\u0430\u0441\u043d\u043e\u0441\u0442\u044c Windows"
#define WINDOWS_TITLE_2 L"Безопасность Windows"

#define AVEST_TITLE_1 L"Avest CSP Bel Pro x64 - \u043a\u043e\u043d\u0442\u0435\u0439\u043d\u0435\u0440 \u043b\u0438\u0447\u043d\u044b\u0445 \u043a\u043b\u044e\u0447\u0435\u0439"
#define AVEST_TITLE_2 L"Avest CSP Bel Pro x64 - контейнер личных ключей"

volatile DWORD g_targetProcessId = 0;
BOOL g_running = TRUE;



BOOL IsWindowTopmost(HWND hwnd) {
	WINDOWINFO wi = { 0 };
	wi.cbSize = sizeof(WINDOWINFO);

	if (GetWindowInfo(hwnd, &wi)) {
		return (wi.dwExStyle & WS_EX_TOPMOST) != 0;
	}
	return FALSE;
}

void SetWindowTopmost(HWND hwnd) {
	if (hwnd != NULL && IsWindow(hwnd)) {
		if (!SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE)) {
			//bypass!!!
			keybd_event(VK_MENU, 0, 0, 0);
			keybd_event(VK_MENU, 0, KEYEVENTF_KEYUP, 0);
			SetForegroundWindow(hwnd);
		}
		wchar_t windowTitle[256];
		GetWindowTextW(hwnd, windowTitle, 256);
		wprintf(L"Window set to TOPMOST: %s\n", windowTitle);
		fflush(stdout);
	}
}

void CheckAndSetTopmost(HWND hwnd) {
	if (hwnd != NULL && IsWindow(hwnd)) {
		if (!IsWindowTopmost(hwnd)) {
			SetWindowTopmost(hwnd);
		}
	}
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
	if (g_targetProcessId == 0) {
		return;
	}
	DWORD windowProcessId = 0;
	wchar_t windowTitle[256];
	GetWindowTextW(hwnd, windowTitle, 256);
	if (event == EVENT_OBJECT_FOCUS || event == EVENT_OBJECT_CREATE || event == EVENT_OBJECT_SHOW) {
		if (wcsstr(windowTitle, WINDOWS_TITLE_1) != NULL || wcsstr(windowTitle, WINDOWS_TITLE_2) != NULL) {
			CheckAndSetTopmost(hwnd);// need admin privileges on win11
		}
	}

	GetWindowThreadProcessId(hwnd, &windowProcessId);
	if (windowProcessId != g_targetProcessId) {
		return;
	}

	wchar_t className[256];
	GetClassNameW(hwnd, className, sizeof(className) / sizeof(wchar_t));
	//wprintf(L"event %d %06X %s %p\n", windowProcessId, event, className, hwnd);
	//fflush(stdout);
	if ((wcsstr(windowTitle, AVEST_TITLE_1) != NULL || wcsstr(windowTitle, AVEST_TITLE_2) != NULL) && IsWindowVisible(hwnd) && event == EVENT_OBJECT_SHOW || event == EVENT_OBJECT_FOCUS) {
		wprintf(L"Avest window! %p, event %d\n", hwnd, event);
		int editCounter = 0;
		HWND firstEdit = NULL;
		HWND thirdEdit = NULL;
		HWND passwordEdit = NULL;
		HWND containerNameEdit = NULL;
		HWND combobox = NULL;
		HWND okButton = NULL;
		TCHAR className[256] = { 0 };
		TCHAR windowText[256] = { 0 };
		TCHAR containerName[256] = { 0 };
		HWND hChild = GetWindow(hwnd, GW_CHILD);
		while (hChild != NULL) {
			GetClassName(hChild, className, 256);
			if (wcsstr(className, L"Button") != NULL) {
				GetWindowText(hChild, windowText, 256);
				if (wcsstr(windowText, L"OK") != NULL) {
					okButton = hChild;
					//wprintf(L"OK button detected! %p\n", okButton);
				}
			}
			else if (wcsstr(className, L"ComboBox") != NULL) {
				combobox = hChild;
				//wprintf(L"ComboBox detected! %p\n", combobox);
			}
			else if (wcsstr(className, L"Edit") != NULL) {
				editCounter++;
				if (firstEdit == NULL) {
					firstEdit = hChild;
				}
				if (editCounter == 3) {
					thirdEdit = hChild;
				}
				LRESULT res = SendMessage(hChild, WM_GETTEXT, 256, (LPARAM)windowText);
				if (IsWindowVisible(hChild)) {
					if (res != 0) {
						if (wcsnlen_s(windowText, sizeof(windowText)) > 0) {
							containerNameEdit = hChild;
							memcpy(containerName, windowText, sizeof(containerName));
						}
					}
					else {
						passwordEdit = hChild;
					}
				}
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
		if (combobox != NULL && passwordEdit == NULL && okButton != NULL) {
			passwordEdit = firstEdit;
		}
		if (combobox != NULL && passwordEdit != NULL && okButton != NULL) {
			TCHAR usbSerial[128] = { 0 };
			SendMessage(combobox, WM_GETTEXT, 128, (LPARAM)usbSerial);
			size_t holder_len = wcsnlen_s(usbSerial, sizeof(usbSerial));
			if (holder_len > 1) {
				int cert_count = 0;
				PCertData certs;
				int err = ReadSavedFile(&certs, &cert_count);
				PCertData certData = NULL;
				if (cert_count > 0) {
					certData = findCertDataByUSBSerialAndContainerName(certs, cert_count, usbSerial, containerName);
					if (certData != NULL) {
						if (certData->password[0]) {
							wprintf(L"Enter password %s\n", certData->password);
							SendMessage(passwordEdit, WM_SETTEXT, 0, (LPARAM)certData->password);
							SendMessage(okButton, BM_CLICK, 0, 0);
						}
					}
				}
				BOOL needSave = FALSE;
				if (certData == NULL) {
					if (certs == NULL) {
						certData = calloc(1, sizeof(CertData));
						certs = certData;
						cert_count = 1;
					}
					else {
						PCertData newCerts = realloc(certs, cert_count + 1);
						if (newCerts != 0) {
							certs = newCerts;
							certData = &certs[cert_count];
							memset(certData, 0, sizeof(CertData));
							cert_count++;
						}
					}
					if (certData != NULL) {
						memcpy(certData->USBSerial, usbSerial, holder_len * sizeof(TCHAR));
						needSave = TRUE;
					}
				}
				if (certData != NULL && certData->ContainerName[0] == '\0' && containerName[0]) {
					memcpy(certData->ContainerName, containerName, sizeof(certData->ContainerName));
					needSave = TRUE;
				}
				if (certData != NULL && certData->Serial[0] == '\0' && containerName[0]) {
					char* serial = getCertSerialByContainerName(containerName);
					if (serial != 0) {
						memcpy(certData->Serial, serial, strnlen_s(serial, sizeof(certData->Serial)));
						free(serial);
						needSave = TRUE;
					}
				}
				if (needSave)
				{
					WriteSavedFile(certs, cert_count);
				}
			}
		}
	}
	else if (IsWindow(hwnd)) {
		RECT rect;
		if (GetWindowRect(hwnd, &rect)) {
			int w = rect.right - rect.left;
			int h = rect.bottom - rect.top;
			if ((w == 416 && h == 139) || (w == 516 && h == 135)) {
				if (event == EVENT_OBJECT_SHOW) {
					PostMessage(hwnd, WM_CLOSE, 0, 0);
					wprintf(L"Close annoying window\n");
				}
			}
			if (w == 416 && h == 389) {//пропустить окно подтверждения доступа к ФИО при авторизации в ИФЮЛ
				PostMessage(hwnd, WM_KEYDOWN, VK_RETURN, 0);
				PostMessage(hwnd, WM_KEYUP, VK_RETURN, 0);
			}
		}
	}
}

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
	DWORD windowProcessId = 0;
	wchar_t windowTitle[256];

	GetWindowThreadProcessId(hwnd, &windowProcessId);

	if (windowProcessId == g_targetProcessId) {
		GetWindowTextW(hwnd, windowTitle, 256);

		if (wcsstr(windowTitle, WINDOWS_TITLE_1) != NULL || wcsstr(windowTitle, WINDOWS_TITLE_2) != NULL) {
			wprintf(L"Existing window found: %s\n", windowTitle);
			CheckAndSetTopmost(hwnd);
			return FALSE;
		}
	}
	return TRUE;
}

void FindExistingWindows(void) {
	wprintf(L"Searching for existing windows...\n");
	fflush(stdout);
	EnumWindows(EnumWindowsProc, 0);
}
#include "dll_data.h"
#include "injector.h"
int WriteToTempFile(const char* filename_only, const char* data, DWORD data_len, WCHAR* output_path, size_t output_path_size) {
	WCHAR temp_path[MAX_PATH];
	WCHAR filename_wide[MAX_PATH];
	HANDLE hFile;
	DWORD bytes_written;
	BOOL write_result;

	MultiByteToWideChar(CP_ACP, 0, filename_only, -1, filename_wide, MAX_PATH);

	DWORD temp_path_len = GetTempPathW(MAX_PATH, temp_path);
	if (temp_path_len == 0 || temp_path_len > MAX_PATH) {
		wcscpy_s(temp_path, MAX_PATH, L".\\");
	}

	swprintf_s(output_path, output_path_size, L"%s%s", temp_path, filename_wide);

	hFile = CreateFileW(
		output_path,
		GENERIC_WRITE,
		0,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (hFile == INVALID_HANDLE_VALUE) {
		return 0;
	}

	write_result = WriteFile(hFile, data, data_len, &bytes_written, NULL);

	CloseHandle(hFile);

	if (write_result && bytes_written == data_len) {
		return 1;
	}

	return 0;
}

//$b = [IO.File]::ReadAllBytes("<path to dll>"); $h = ($b | % {'0x{0:X2}'-f$_})-join', '; "unsigned char dll_bytes[]={$h}; unsigned int dll_bytes_len=$($b.Length);" > dll_data.h
void injectDll() {
	wchar_t dll_path[512];
	WriteToTempFile("NTClientTool_dll.dll", dll_bytes, dll_bytes_len, dll_path, sizeof(dll_path) / sizeof(wchar_t));
	injector_t* injector;
	void* handle;

	if (injector_attach(&injector, g_targetProcessId) != 0) {
		printf("ATTACH ERROR: %s\n", injector_error());
		return;
	}

	if (injector_inject_w(injector, dll_path, NULL) != 0) {
		printf("INJECT ERROR: %s\n", injector_error());
	}
	else {
		printf("Successfully injected %S to %d\n", dll_path, g_targetProcessId);
	}

	injector_detach(injector);
}

BOOL WINAPI ConsoleHandler(DWORD signal) {
	if (signal == CTRL_C_EVENT || signal == CTRL_CLOSE_EVENT) {
		wprintf(L"\nShutting down...\n");
		g_running = FALSE;
		PostQuitMessage(0);
		return TRUE;
	}
	return FALSE;
}


DWORD WINAPI HookThread(LPVOID lpParam) {

	HWINEVENTHOOK g_hHook = SetWinEventHook(
		EVENT_OBJECT_CREATE,
		EVENT_OBJECT_SELECTIONWITHIN,
		NULL,
		WinEventProc,
		0,
		0,
		WINEVENT_OUTOFCONTEXT
	);

	if (g_hHook == NULL) {
		wprintf(L"Failed to install EVENT_OBJECT hook. Error: %lu\n", GetLastError());
		fflush(stdout);
		return 0;
	}


	wprintf(L"Hooks installed successfully\n");
	fflush(stdout);

	MSG msg;
	//use this code for single process
	//HANDLE hProcess = OpenProcess(SYNCHRONIZE, FALSE, g_targetProcessId);
	//while (true) {
	//	DWORD result = MsgWaitForMultipleObjects(
	//		1, &hProcess,
	//		FALSE, INFINITE,
	//		QS_ALLINPUT
	//	);

	//	if (result == WAIT_OBJECT_0) {
	//		break;
	//	}
	//	else if (result == WAIT_OBJECT_0 + 1) {
	//		while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
	//			if (msg.message == WM_QUIT) {
	//				break;
	//			}
	//			TranslateMessage(&msg);
	//			DispatchMessage(&msg);
	//		}
	//	}
	//}
	//CloseHandle(hProcess);
	BOOL result;
	while ((result = GetMessage(&msg, NULL, 0, 0)) != 0) {
		if (result == -1) {
			DWORD error = GetLastError();
			wprintf(L"Hook error %lu\n", error);
			break;
		}
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	wprintf(L"Hook thread ended\n");
	fflush(stdout);
	UnhookWinEvent(g_hHook);
	return 0;
}

BOOL IsRunningFromConsole() {
	HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);

	if (hStdOut == NULL || hStdOut == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	DWORD dwFileType = GetFileType(hStdOut);
	if (dwFileType != FILE_TYPE_CHAR) {
	}

	CONSOLE_SCREEN_BUFFER_INFO csbi;
	if (!GetConsoleScreenBufferInfo(hStdOut, &csbi)) {
		return FALSE;
	}

	HWND hConsoleWnd = GetConsoleWindow();
	if (hConsoleWnd == NULL) {
		return FALSE;
	}

	DWORD dwProcessId;
	GetWindowThreadProcessId(hConsoleWnd, &dwProcessId);

	if (dwProcessId != GetCurrentProcessId()) {
		return TRUE;
	}

	HANDLE hParent = NULL;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot != INVALID_HANDLE_VALUE) {
		PROCESSENTRY32 pe;
		pe.dwSize = sizeof(PROCESSENTRY32);

		if (Process32First(hSnapshot, &pe)) {
			do {
				if (pe.th32ProcessID == GetCurrentProcessId()) {
					HANDLE hParentProcess = OpenProcess(
						PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
						FALSE, pe.th32ParentProcessID
					);
					if (hParentProcess) {
						char szParentPath[MAX_PATH];
						if (GetModuleFileNameExA(hParentProcess, NULL,
							szParentPath, MAX_PATH)) {
							char* szFileName = strrchr(szParentPath, '\\');
							if (szFileName) {
								szFileName++;
								if (_stricmp(szFileName, "cmd.exe") == 0 ||
									_stricmp(szFileName, "powershell.exe") == 0 ||
									_stricmp(szFileName, "VsDebugConsole.exe") == 0) {
									return TRUE;
								}
							}
						}
						CloseHandle(hParentProcess);
					}
					break;
				}
			} while (Process32Next(hSnapshot, &pe));
		}
		CloseHandle(hSnapshot);
	}
	return FALSE;
}

int main() {
	HANDLE hMutex = CreateMutexA(NULL, TRUE, "Global\\NTClientToolMutex");
	if (hMutex == NULL) {
		return 1;
	}
	if (!IsRunningFromConsole()) {
		FreeConsole();
	}
	if (GetLastError() == ERROR_ALREADY_EXISTS) {
		wprintf(L"NTClientTool already running\n");
		CloseHandle(hMutex);
		return 1;
	}

	SetConsoleCtrlHandler(ConsoleHandler, TRUE);
	setlocale(LC_ALL, "Russian");
	wprintf(L"=== NTClientSoftware tool ===\n");
	wprintf(L"Waiting for NTClientSoftware.exe process...\n");
	wprintf(L"Press Ctrl+C to exit\n\n");
	fflush(stdout);

	DWORD lastProcessId = 0;
	HANDLE hook = CreateThread(0, 512 * 1024, HookThread, 0, 0, 0);
	ULONGLONG lastCheckTime = 0;
	while (g_running) {
		ULONGLONG curTime = GetTickCount64();
		if (curTime - lastCheckTime > (g_targetProcessId == 0 ? 250 : 5000)) {
			lastCheckTime = curTime;
			DWORD currentProcessId = GetProcessIdByName(L"NTClientSoftware.exe");
			if (currentProcessId != 0 && currentProcessId != lastProcessId) {
				wprintf(L"NTClientSoftware.exe detected! PID: %lu\n", currentProcessId);
				g_targetProcessId = currentProcessId;
				FindExistingWindows();
				injectDll();
				lastProcessId = currentProcessId;
			}
			else if (currentProcessId == 0) {
				if (lastProcessId != 0) {
					wprintf(L"Process terminated (PID: %lu)\n", lastProcessId);
					fflush(stdout);
					lastProcessId = 0;
					g_targetProcessId = 0;
				}
			}
		}
		Sleep(250);
	}
	if (hook != NULL) {
		CloseHandle(hook);
	}

	wprintf(L"Program terminated\n");
	fflush(stdout);
	return 0;
}