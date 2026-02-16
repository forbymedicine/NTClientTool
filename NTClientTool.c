#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdbool.h>
#include <locale.h>
#include <psapi.h>
#pragma comment(lib, "user32.lib")

#define MAX_LINE_LEN 512
#define MAX_PATH_LEN 260

volatile DWORD g_targetProcessId = 0;
BOOL g_running = TRUE;

BOOL GetProcessIdByName(const wchar_t* processName) {
	DWORD processId = 0;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (snapshot != INVALID_HANDLE_VALUE) {
		PROCESSENTRY32W processEntry;
		processEntry.dwSize = sizeof(processEntry);

		if (Process32FirstW(snapshot, &processEntry)) {
			do {
				if (_wcsicmp(processEntry.szExeFile, processName) == 0) {
					processId = processEntry.th32ProcessID;
					break;
				}
			} while (Process32NextW(snapshot, &processEntry));
		}
		CloseHandle(snapshot);
	}
	return processId;
}

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

wchar_t* ReadPasswordFromFile(wchar_t* avName) {
	wchar_t filePath[MAX_PATH_LEN];
	FILE* file;
	wchar_t line[MAX_LINE_LEN];
	wchar_t* result = NULL;
	errno_t err;

	DWORD envResult = GetEnvironmentVariableW(L"APPDATA", filePath, MAX_PATH_LEN);
	if (envResult == 0 || envResult > MAX_PATH_LEN) {
		wprintf(L"Failed to get path to APPDATA\n");
		return NULL;
	}

	if (wcslen(filePath) + wcslen(L"\\Avest\\saved.txt") >= MAX_PATH_LEN) {
		wprintf(L"Too long path\n");
		return NULL;
	}
	wcscat_s(filePath, MAX_PATH_LEN, L"\\Avest\\saved.txt");

	err = _wfopen_s(&file, filePath, L"r");
	if (err != 0 || file == NULL) {
		wprintf(L"Failed to open %s (code: %d)\n", filePath, err);
		return NULL;
	}

	while (fgetws(line, MAX_LINE_LEN, file) != NULL) {
		size_t len = wcslen(line);

		if (len > 0 && (line[len - 1] == L'\n' || line[len - 1] == L'\r')) {
			line[len - 1] = L'\0';
			len--;
		}
		if (len > 0 && line[len - 1] == L'\r') {
			line[len - 1] = L'\0';
			len--;
		}

		wchar_t* colonPos = wcschr(line, L':');
		if (colonPos != NULL) {
			size_t nameLen = colonPos - line;

			if (nameLen > 0 && nameLen < MAX_LINE_LEN) {
				wchar_t* currentName = (wchar_t*)malloc((nameLen + 1) * sizeof(wchar_t));
				if (currentName == NULL) {
					continue;
				}

				wcsncpy_s(currentName, nameLen + 1, line, nameLen);
				currentName[nameLen] = L'\0';

				if (wcscmp(currentName, avName) == 0) {
					wchar_t* valueStart = colonPos + 1;
					size_t valueLen = wcslen(valueStart);

					if (valueLen > 0) {
						result = (wchar_t*)malloc((valueLen + 1) * sizeof(wchar_t));
						if (result != NULL) {
							wcscpy_s(result, valueLen + 1, valueStart);
						}
					}
					free(currentName);
					break;
				}
				free(currentName);
			}
		}
	}

	fclose(file);
	return result;
}
DWORD WINAPI SelectCertificateThread(LPVOID lpParam) {
	wchar_t* param = ReadPasswordFromFile(L"skip_cert_window");
	if (param != 0) {
		if (wcsstr(param, L"true") == NULL) {
			free(param);
			return;
		}
		free(param);
	}
	else {
		return;
	}

	HWND hwnd = (HWND)lpParam;
	BOOL press = FALSE;
	for (int i = 0; i < 25; i++) {
		RECT rect;
		if (GetWindowRect(hwnd, &rect)) {
			int w = rect.right - rect.left;
			int h = rect.bottom - rect.top;
			if (w < 900 && h < 900) {
				press = TRUE;
				break;
			}
		}
		Sleep(200);
	}
	if (!press) {
		return;
	}
	RECT rect;
	int w = 0;
	int h = 0;
	if (GetWindowRect(hwnd, &rect)) {
		w = rect.right - rect.left;
		h = rect.bottom - rect.top;
	}
	INPUT inputs[6] = { 0 };
	int keyCount = 0;
	//355 - win10, without name
	//336 - win10, with name
	//389 - win11, without name
	//370 - win11, with name
	if (w == 456 && (h == 355 || h == 336 || h == 389 || h == 370)) {//single sertificate in user
		// Tab down
		inputs[0].type = INPUT_KEYBOARD;
		inputs[0].ki.wVk = VK_TAB;
		// Tab up
		inputs[1].type = INPUT_KEYBOARD;
		inputs[1].ki.wVk = VK_TAB;
		inputs[1].ki.dwFlags = KEYEVENTF_KEYUP;
		// Enter down
		inputs[2].type = INPUT_KEYBOARD;
		inputs[2].ki.wVk = VK_RETURN;
		// Enter up
		inputs[3].type = INPUT_KEYBOARD;
		inputs[3].ki.wVk = VK_RETURN;
		inputs[3].ki.dwFlags = KEYEVENTF_KEYUP;
		keyCount = 4;
	}
	//else if (w == 456 && h == 373) {//multiply sertificate in user
	//	// Tab down
	//	inputs[0].type = INPUT_KEYBOARD;
	//	inputs[0].ki.wVk = VK_TAB;
	//	// Tab up
	//	inputs[1].type = INPUT_KEYBOARD;
	//	inputs[1].ki.wVk = VK_TAB;
	//	inputs[1].ki.dwFlags = KEYEVENTF_KEYUP;
	//	// Tab down
	//	inputs[2].type = INPUT_KEYBOARD;
	//	inputs[2].ki.wVk = VK_TAB;
	//	// Tab up
	//	inputs[3].type = INPUT_KEYBOARD;
	//	inputs[3].ki.wVk = VK_TAB;
	//	inputs[3].ki.dwFlags = KEYEVENTF_KEYUP;
	//	// Enter down
	//	inputs[4].type = INPUT_KEYBOARD;
	//	inputs[4].ki.wVk = VK_RETURN;
	//	// Enter up
	//	inputs[5].type = INPUT_KEYBOARD;
	//	inputs[5].ki.wVk = VK_RETURN;
	//	inputs[5].ki.dwFlags = KEYEVENTF_KEYUP;
	//	keyCount = 6;
	//}
	if (keyCount > 0) {
		SetForegroundWindow(hwnd);
		Sleep(75);
		SetForegroundWindow(hwnd);
		Sleep(75);
		SendInput(keyCount, inputs, sizeof(INPUT));

		//wprintf(L"Send button for select certificate!\n");
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
		if (wcsstr(windowTitle, L"Безопасность Windows") != NULL) {
			CheckAndSetTopmost(hwnd);// need admin privileges on win11
			if (IsWindowVisible(hwnd)) {
				HANDLE pressThread = CreateThread(0, 128 * 1024, SelectCertificateThread, hwnd, 0, 0);
				if (pressThread != 0) {
					CloseHandle(pressThread);
				}
			}
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

	if (wcsstr(windowTitle, L"Avest CSP Bel Pro x64 - контейнер личных ключей") != NULL && IsWindowVisible(hwnd) && event == EVENT_OBJECT_SHOW || event == EVENT_OBJECT_FOCUS) {
		wprintf(L"Avest! %d\n", event);

		HWND passwordEdit = NULL;
		HWND combobox = NULL;
		HWND okButton = NULL;
		TCHAR className[256] = { 0 };
		TCHAR windowText[256] = { 0 };
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
				LRESULT res = SendMessage(hChild, WM_GETTEXT, 256, (LPARAM)windowText);
				if (res == 0 && IsWindowVisible(hChild)) {
					passwordEdit = hChild;
					//wprintf(L"Password edit detected! %p\n", passwordEdit);
				}
			}

			//RECT rect;
			//GetWindowRect(hChild, &rect);
			//printf("%d. HWND: %p\n", count, hChild);
			//printf("   Class: %S\n", className);
			//printf("   Text: %S\n", windowText);
			//printf("   Rect: (%d,%d)-(%d,%d)\n",
			//	rect.left, rect.top, rect.right, rect.bottom);
			//printf("\n");

			hChild = GetWindow(hChild, GW_HWNDNEXT);
		}
		if (combobox != NULL && passwordEdit != NULL && okButton != NULL) {
			TCHAR holderName[128] = { 0 };
			SendMessage(combobox, WM_GETTEXT, 128, (LPARAM)holderName);
			size_t pass_len = wcsnlen_s(holderName, sizeof(holderName));
			if (pass_len > 1) {
				wchar_t* password = ReadPasswordFromFile(holderName);
				if (password != NULL) {
					wprintf(L"Enter password\n");
					SendMessage(passwordEdit, WM_SETTEXT, pass_len, password);
					SendMessage(okButton, BM_CLICK, 0, 0);
					free(password);
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
		}
	}
}

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
	DWORD windowProcessId = 0;
	wchar_t windowTitle[256];

	GetWindowThreadProcessId(hwnd, &windowProcessId);

	if (windowProcessId == g_targetProcessId) {
		GetWindowTextW(hwnd, windowTitle, 256);

		if (wcsstr(windowTitle, L"Безопасность Windows") != NULL) {
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