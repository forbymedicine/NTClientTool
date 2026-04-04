#define _CRT_SECURE_NO_WARNINGS
#include "utils.h"
#include <windows.h>
#include <setupapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <shlobj.h>
#include <locale.h>

#define MAX_CERTS 256
#pragma comment(lib, "setupapi.lib")
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "cryptui.lib")

DWORD GetProcessIdByName(const wchar_t* processName) {
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

void serialToString(char* dest, CRYPT_INTEGER_BLOB* pSerial) {
	if (pSerial->cbData > 0) {
		int offset = 0;
		const int max_output_len = SERIAL_MAX_SIZE - 1;

		for (int i = pSerial->cbData - 1; i >= 0 && offset < max_output_len; i--) {
			int written = sprintf_s(dest + offset, SERIAL_MAX_SIZE - offset, "%02X", (unsigned char)pSerial->pbData[i]);
			if (written <= 0) break;
			offset += written;
		}
		dest[offset] = '\0';
	}
	else {
		dest[0] = '\0';
	}
}

BOOL serial_cmp(CRYPT_INTEGER_BLOB* pSerial, char* serial) {
	char hexStr[SERIAL_MAX_SIZE];
	int offset = 0;

	if (pSerial == NULL || pSerial->pbData == NULL || serial == NULL || pSerial->pbData == 0) {
		return FALSE;
	}
	serialToString(hexStr, pSerial);
	if (_stricmp(hexStr, serial) == 0) {
		return TRUE;
	}
	return FALSE;
}

#define PREFIX_AVPASS L"AvPass S/N "
#define PREFIX_AVBIGN L"AvBign S/N "
#define AV_PREFIX_LEN 11  // "AvPass S/N " и "AvBign S/N " имеют одинаковую длину 11 символов
int usb_serial_cmp(wchar_t* serial1, wchar_t* serial2) {
	if (serial1 == NULL || serial2 == NULL) {
		return -2;
	}

	BOOL has_prefix1_avpass = (wcsncmp(serial1, PREFIX_AVPASS, AV_PREFIX_LEN) == 0);
	BOOL has_prefix1_avbign = (wcsncmp(serial1, PREFIX_AVBIGN, AV_PREFIX_LEN) == 0);
	BOOL has_prefix2_avpass = (wcsncmp(serial2, PREFIX_AVPASS, AV_PREFIX_LEN) == 0);
	BOOL has_prefix2_avbign = (wcsncmp(serial2, PREFIX_AVBIGN, AV_PREFIX_LEN) == 0);

	BOOL has_prefix1 = has_prefix1_avpass || has_prefix1_avbign;
	BOOL has_prefix2 = has_prefix2_avpass || has_prefix2_avbign;

	wchar_t* code1 = serial1;
	wchar_t* code2 = serial2;

	if (has_prefix1) {
		code1 = serial1 + AV_PREFIX_LEN;
	}
	if (has_prefix2) {
		code2 = serial2 + AV_PREFIX_LEN;
	}

	int cmp_result = wcscmp(code1, code2);

	if (cmp_result != 0) {
		return cmp_result;
	}

	if (!has_prefix1 && !has_prefix2) {
		return 0;
	}

	if (has_prefix1 && has_prefix2) {
		BOOL same_prefix = (has_prefix1_avpass && has_prefix2_avpass) ||
			(has_prefix1_avbign && has_prefix2_avbign);

		if (same_prefix) {
			return 0;
		}
		else {
			return -1;
		}
	}

	return 0;
}

char* getCertSerialByContainerName(wchar_t* containerName) {

	char* hexStr = calloc(1, SERIAL_MAX_SIZE);
	if (!hexStr) {
		return NULL;
	}
	HCERTSTORE hStore = CertOpenSystemStoreW(0, L"MY");
	if (!hStore) {
		free(hexStr);
		return 0;
	}
	PCCERT_CONTEXT pCert = NULL;
	while ((pCert = CertEnumCertificatesInStore(hStore, pCert)) != NULL) {

		DWORD dwSize = 0;
		if (CertGetCertificateContextProperty(pCert, CERT_KEY_PROV_INFO_PROP_ID, NULL, &dwSize)) {
			PCRYPT_KEY_PROV_INFO pInfo = (PCRYPT_KEY_PROV_INFO)malloc(dwSize);
			if (pInfo && CertGetCertificateContextProperty(pCert, CERT_KEY_PROV_INFO_PROP_ID, pInfo, &dwSize)) {
				if (wcscmp(pInfo->pwszContainerName, containerName) == 0) {
					serialToString(hexStr, &pCert->pCertInfo->SerialNumber);
					free(pInfo);
					CertCloseStore(hStore, 0);

					return hexStr;
				}
				free(pInfo);
			}
		}
	}
	CertCloseStore(hStore, 0);
	free(hexStr);
	return 0;
}
PCCERT_CONTEXT findCertContext(wchar_t* containerName, char* serial) {
	HCERTSTORE hStore = CertOpenSystemStoreW(0, L"MY");
	if (!hStore) {
		return NULL;
	}

	PCCERT_CONTEXT pCert = NULL;
	PCCERT_CONTEXT pResult = NULL;

	if (containerName != NULL && serial != NULL) {
		pCert = NULL;
		while ((pCert = CertEnumCertificatesInStore(hStore, pCert)) != NULL) {
			DWORD dwSize = 0;
			if (CertGetCertificateContextProperty(pCert, CERT_KEY_PROV_INFO_PROP_ID, NULL, &dwSize)) {
				PCRYPT_KEY_PROV_INFO pInfo = (PCRYPT_KEY_PROV_INFO)malloc(dwSize);
				if (pInfo && CertGetCertificateContextProperty(pCert, CERT_KEY_PROV_INFO_PROP_ID, pInfo, &dwSize)) {
					BOOL nameMatch = (pInfo->pwszContainerName &&
						wcscmp(pInfo->pwszContainerName, containerName) == 0);
					BOOL serialMatch = FALSE;
					if (nameMatch) {
						serialMatch = serial_cmp(&pCert->pCertInfo->SerialNumber, serial);
					}

					if (nameMatch && serialMatch) {
						pResult = CertDuplicateCertificateContext(pCert);
						free(pInfo);
						break;
					}
					free(pInfo);
				}
			}
		}

		if (pResult) {
			if (pCert) {
				CertFreeCertificateContext(pCert);
			}
			CertCloseStore(hStore, 0);
			return pResult;
		}
		if (pCert) {
			CertFreeCertificateContext(pCert);
			pCert = NULL;
		}
	}

	if (containerName != NULL) {
		pCert = NULL;
		while ((pCert = CertEnumCertificatesInStore(hStore, pCert)) != NULL) {
			DWORD dwSize = 0;
			if (CertGetCertificateContextProperty(pCert, CERT_KEY_PROV_INFO_PROP_ID, NULL, &dwSize)) {
				PCRYPT_KEY_PROV_INFO pInfo = (PCRYPT_KEY_PROV_INFO)malloc(dwSize);
				if (pInfo && CertGetCertificateContextProperty(pCert, CERT_KEY_PROV_INFO_PROP_ID, pInfo, &dwSize)) {
					if (pInfo->pwszContainerName && wcscmp(pInfo->pwszContainerName, containerName) == 0) {
						pResult = CertDuplicateCertificateContext(pCert);
						free(pInfo);
						break;
					}
					free(pInfo);
				}
			}
		}

		if (pResult) {
			if (pCert) {
				CertFreeCertificateContext(pCert);
			}
			CertCloseStore(hStore, 0);
			return pResult;
		}

		if (pCert) {
			CertFreeCertificateContext(pCert);
			pCert = NULL;
		}
	}

	if (serial != NULL) {
		pCert = NULL;
		while ((pCert = CertEnumCertificatesInStore(hStore, pCert)) != NULL) {
			if (serial_cmp(&pCert->pCertInfo->SerialNumber, serial)) {
				pResult = CertDuplicateCertificateContext(pCert);
				break;
			}
		}

		if (pResult) {
			if (pCert) {
				CertFreeCertificateContext(pCert);
			}
			CertCloseStore(hStore, 0);
			return pResult;
		}
	}

	if (pCert) {
		CertFreeCertificateContext(pCert);
	}
	CertCloseStore(hStore, 0);
	return NULL;
}

BOOL IsCertificateDateValid(FILETIME ftNotBefore, FILETIME ftNotAfter) {
	SYSTEMTIME stCurrent;
	FILETIME ftCurrent;
	GetSystemTime(&stCurrent);
	SystemTimeToFileTime(&stCurrent, &ftCurrent);
	LONGLONG llCurrent = ((LONGLONG)ftCurrent.dwHighDateTime << 32) | ftCurrent.dwLowDateTime;
	LONGLONG llNotBefore = ((LONGLONG)ftNotBefore.dwHighDateTime << 32) | ftNotBefore.dwLowDateTime;
	LONGLONG llNotAfter = ((LONGLONG)ftNotAfter.dwHighDateTime << 32) | ftNotAfter.dwLowDateTime;
	if (llCurrent < llNotBefore) {
		return FALSE;
	}
	else if (llCurrent > llNotAfter) {
		return FALSE;
	}
	return TRUE;
}

void readMyCerificates(PCertData certs, int* count) {
	if (!count) return;

	HCERTSTORE hStore = CertOpenSystemStoreW(0, L"MY");
	if (!hStore) {
		*count = 0;
		return;
	}

	if (certs == NULL) {
		int certCount = 0;
		PCCERT_CONTEXT pCert = NULL;
		while ((pCert = CertEnumCertificatesInStore(hStore, pCert)) != NULL) {
			certCount++;
		}
		*count = certCount;
		CertCloseStore(hStore, 0);
		return;
	}

	if (*count <= 0) {
		CertCloseStore(hStore, 0);
		return;
	}

	int index = 0;
	PCCERT_CONTEXT pCert = NULL;

	while (index < *count &&
		(pCert = CertEnumCertificatesInStore(hStore, pCert)) != NULL) {
		char* hexStr = certs[index].Serial;
		serialToString(hexStr, &pCert->pCertInfo->SerialNumber);
		CRYPT_INTEGER_BLOB* pSerial = &pCert->pCertInfo->SerialNumber;
		DWORD dwSize = 0;
		if (CertGetCertificateContextProperty(pCert, CERT_KEY_PROV_INFO_PROP_ID, NULL, &dwSize)) {
			PCRYPT_KEY_PROV_INFO pInfo = (PCRYPT_KEY_PROV_INFO)malloc(dwSize);
			if (pInfo && CertGetCertificateContextProperty(pCert, CERT_KEY_PROV_INFO_PROP_ID, pInfo, &dwSize)) {
				if (pInfo->pwszContainerName) {
					wcsncpy_s(certs[index].ContainerName, sizeof(certs[index].ContainerName) / sizeof(wchar_t), pInfo->pwszContainerName, 127);
				}
				free(pInfo);
			}
		}
		index++;
	}

	*count = index;
	CertCloseStore(hStore, 0);
}


void getPluggedUSBSerialNumbers(PCertData certs, int* count) {
	HDEVINFO hDevInfo = NULL;
	SP_DEVINFO_DATA devInfoData;
	DWORD deviceIndex = 0;
	DWORD deviceCount = 0;
	hDevInfo = SetupDiGetClassDevs(&GUID_DEVINTERFACE_USB_DEVICE,
		NULL,
		NULL,
		DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);

	if (hDevInfo == INVALID_HANDLE_VALUE) {
		*count = 0;
		return;
	}

	devInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
	int i = 0;
	while (SetupDiEnumDeviceInfo(hDevInfo, deviceIndex, &devInfoData)) {
		deviceIndex++;
		deviceCount++;
		BYTE buffer[64] = { 0 };
		DWORD dataType = 0;

		if (SetupDiGetDeviceInstanceIdA(hDevInfo, &devInfoData, (PSTR)buffer, sizeof(buffer), NULL)) {
			char* instanceId = (char*)buffer;
			if (instanceId && *instanceId) {
				char* lastBackslash = strrchr(instanceId, '\\');
				if (lastBackslash && *(lastBackslash + 1)) {
					char* serial = lastBackslash + 1;

					rsize_t len = strnlen_s(serial, sizeof(buffer) - (serial - (char*)buffer));
					if (len >= 12 && len <= 14 && strncmp("AVP", serial, 3) == 0) {
						if (certs != NULL) {
							size_t converted = 0;
							errno_t err = mbstowcs_s(
								&converted,
								certs[i].USBSerial,
								sizeof(certs[i].USBSerial) / sizeof(wchar_t),
								serial,
								_TRUNCATE
							);
							if (err != 0 || converted == 0) {
								certs[i].USBSerial[0] = L'\0';
							}
						}
						i++;
					}
				}
			}
		}
	}
	*count = i;
}

PCertData findSavedCertDataByUSBSerial(wchar_t* usbSerial) {
	PCertData certs = NULL;
	int count = 0;
	int result = ReadSavedFile(&certs, &count);
	PCertData pResult = NULL;
	if (result > 0) {
		int match_count = 0;
		PCertData cert = NULL;
		for (int i = 0; i < count; i++) {
			if (usb_serial_cmp((wchar_t*)&certs[i].USBSerial, usbSerial) == 0) {
				match_count++;
				cert = &certs[i];
			}
		}
		if (match_count == 1) {
			pResult = malloc(sizeof(CertData));
			if (pResult != 0) {
				memcpy(pResult, cert, sizeof(CertData));
			}
		}
		else if (match_count > 1) {
			//ситуация, когда на одном USB есть несколько сертификатов либо в сохранённом файле остался просроченный сертификат
			for (int i = 0; i < count; i++) {
				if (usb_serial_cmp((wchar_t*)&certs[i].USBSerial, usbSerial) == 0) {
					PCCERT_CONTEXT context = findCertContext((wchar_t*)&certs[i].ContainerName, (char*)&certs[i].Serial);
					if (context != NULL) {
						FILETIME NotBefore = context->pCertInfo->NotBefore;
						FILETIME NotAfter = context->pCertInfo->NotAfter;
						CertFreeCertificateContext(context);
						if (IsCertificateDateValid(NotBefore, NotAfter)) {
							pResult = malloc(sizeof(CertData));
							if (pResult != 0) {
								memcpy(pResult, &certs[i], sizeof(CertData));
							}
							break;
						}
					}
				}
			}
			if (pResult == NULL) {
				pResult = malloc(sizeof(CertData));
				if (pResult != 0) {
					memcpy(pResult, cert, sizeof(CertData));
				}
			}
		}
		free(certs);
	}
	return pResult;
}

PCertData findCertDataByUSBSerialAndContainerName(PCertData certs, int count, wchar_t* usbSerial, wchar_t* containerName) {
	for (int i = 0; i < count; i++) {
		if (usbSerial != NULL && usbSerial[0] && containerName != NULL && containerName[0]) {
			if (usb_serial_cmp((wchar_t*)&certs[i].USBSerial, usbSerial) == 0 && wcscmp(containerName, (wchar_t*)&certs[i].ContainerName) == 0) {
				return &certs[i];
			}
		}
	}
	for (int i = 0; i < count; i++) {
		if (usbSerial != NULL && usbSerial[0]) {
			if (usb_serial_cmp((wchar_t*)&certs[i].USBSerial, usbSerial) == 0) {
				return &certs[i];
			}
		}
	}
	for (int i = 0; i < count; i++) {
		if (containerName != NULL && containerName[0]) {
			if (wcscmp(containerName, (wchar_t*)&certs[i].ContainerName) == 0) {
				return &certs[i];
			}
		}
	}
	return 0;
}

int ReadSavedFile(PCertData* outArray, int* outCount) {
	wchar_t filePath[MAX_PATH];
	FILE* file;
	wchar_t line[512];
	PCertData certArray = NULL;
	int certCount = 0;
	int maxCerts = MAX_CERTS;
	errno_t err;

	*outArray = NULL;
	*outCount = 0;

	DWORD envResult = GetEnvironmentVariableW(L"APPDATA", filePath, MAX_PATH);
	if (envResult == 0 || envResult > MAX_PATH) {
		return -1;
	}

	if (wcslen(filePath) + wcslen(L"\\Avest\\saved.txt") >= MAX_PATH) {
		return -1;
	}
	wcscat_s(filePath, MAX_PATH, L"\\Avest\\saved.txt");

	err = _wfopen_s(&file, filePath, L"r, ccs=UTF-8");
	if (err != 0 || file == NULL) {
		return -1;
	}

	certArray = (PCertData)calloc(maxCerts, sizeof(CertData));
	if (!certArray) {
		fclose(file);
		return -1;
	}

	while (fgetws(line, 512, file) != NULL) {
		size_t len = wcslen(line);
		if (len > 0 && (line[len - 1] == L'\n' || line[len - 1] == L'\r')) {
			line[len - 1] = L'\0';
			len--;
		}
		if (len > 0 && line[len - 1] == L'\r') {
			line[len - 1] = L'\0';
			len--;
		}

		if (len == 0) {
			continue;
		}

		wchar_t* firstColon = wcschr(line, L':');
		if (firstColon == NULL) {
			continue;
		}

		wchar_t* secondColon = wcschr(firstColon + 1, L':');
		if (secondColon == NULL) {
			// USBSerial:password

			size_t usbLen = firstColon - line;
			if (usbLen > 0 && usbLen < sizeof(((CertData*)0)->USBSerial)) {
				wcsncpy_s(certArray[certCount].USBSerial,
					sizeof(certArray[certCount].USBSerial) / sizeof(wchar_t),
					line, usbLen);
			}

			wchar_t* passwordStart = firstColon + 1;
			size_t passwordLen = wcslen(passwordStart);
			if (passwordLen > 0 && passwordLen < sizeof(certArray[certCount].password) / sizeof(wchar_t)) {
				wcscpy_s(certArray[certCount].password,
					sizeof(certArray[certCount].password) / sizeof(wchar_t),
					passwordStart);
			}
		}
		else {
			// USBSerial:password:Serial:ContainerName
			wchar_t* thirdColon = wcschr(secondColon + 1, L':');

			// USBSerial
			size_t usbLen = firstColon - line;
			if (usbLen > 0 && usbLen < sizeof(((CertData*)0)->USBSerial)) {
				wcsncpy_s(certArray[certCount].USBSerial,
					sizeof(certArray[certCount].USBSerial) / sizeof(wchar_t),
					line, usbLen);
			}

			// Password
			wchar_t* passwordStart = firstColon + 1;
			size_t passwordLen = secondColon - passwordStart;
			if (passwordLen > 0 && passwordLen < sizeof(certArray[certCount].password) / sizeof(wchar_t)) {
				wcsncpy_s(certArray[certCount].password,
					sizeof(certArray[certCount].password) / sizeof(wchar_t),
					passwordStart, passwordLen);
			}
			// Serial
			wchar_t* serialStart = secondColon + 1;
			size_t serialLen;

			if (thirdColon != NULL) {
				serialLen = thirdColon - serialStart;
			}
			else {
				serialLen = wcslen(serialStart);
			}

			if (serialLen > 0 && serialLen < sizeof(certArray[certCount].Serial)) {
				WideCharToMultiByte(CP_UTF8, 0, serialStart, (int)serialLen,
					certArray[certCount].Serial, sizeof(certArray[certCount].Serial) - 1,
					NULL, NULL);
				certArray[certCount].Serial[serialLen] = '\0';
			}

			if (thirdColon != NULL) {
				wchar_t* containerStart = thirdColon + 1;
				size_t containerLen = wcslen(containerStart);

				if (containerLen > 0 && containerLen < sizeof(certArray[certCount].ContainerName) / sizeof(wchar_t)) {
					wcscpy_s(certArray[certCount].ContainerName,
						sizeof(certArray[certCount].ContainerName) / sizeof(wchar_t),
						containerStart);
				}
			}
		}

		certCount++;

		if (certCount >= maxCerts) {
			size_t old_size = maxCerts * sizeof(CertData);
			maxCerts += MAX_CERTS;
			size_t new_size = maxCerts * sizeof(CertData);
			PCertData newArray = (PCertData)realloc(certArray, maxCerts * sizeof(CertData));
			if (!newArray) {
				free(certArray);
				fclose(file);
				return -1;
			}
			memset((char*)newArray + old_size, 0, (new_size - old_size) * sizeof(int));
			certArray = newArray;
		}
	}

	fclose(file);

	if (certCount == 0) {
		free(certArray);
		return 0;
	}

	*outArray = certArray;
	*outCount = certCount;

	return certCount;
}

int WriteSavedFile(PCertData certArray, int certCount) {
	wchar_t filePath[MAX_PATH];
	FILE* file;
	errno_t err;

	if (certArray == NULL || certCount <= 0) {
		wprintf(L"Invalid input parameters\n");
		return -1;
	}

	DWORD envResult = GetEnvironmentVariableW(L"APPDATA", filePath, MAX_PATH);
	if (envResult == 0 || envResult > MAX_PATH) {
		wprintf(L"Failed to get path to APPDATA\n");
		return -1;
	}

	if (wcslen(filePath) + wcslen(L"\\Avest\\saved.txt") >= MAX_PATH) {
		wprintf(L"Too long path\n");
		return -1;
	}
	wcscat_s(filePath, MAX_PATH, L"\\Avest\\saved.txt");

	err = _wfopen_s(&file, filePath, L"w, ccs=UTF-8");
	if (err != 0 || file == NULL) {
		wprintf(L"Failed to open %s for writing (code: %d)\n", filePath, err);
		return -1;
	}

	for (int i = 0; i < certCount; i++) {
		BOOL hasSerialAndContainer = (certArray[i].Serial[0] &&
			certArray[i].ContainerName[0] != L'\0');

		wchar_t serialWide[64];
		if (hasSerialAndContainer) {
			MultiByteToWideChar(CP_UTF8, 0, certArray[i].Serial, -1,
				serialWide, sizeof(serialWide) / sizeof(wchar_t));
		}

		if (hasSerialAndContainer) {
			fwprintf(file, L"%s:%s:%s:%s%s",
				certArray[i].USBSerial,
				certArray[i].password,
				serialWide,
				certArray[i].ContainerName, (i == certCount - 1) ? L"" : L"\n");
		}
		else {
			fwprintf(file, L"%s:%s%s",
				certArray[i].USBSerial,
				certArray[i].password,
				(i == certCount - 1) ? L"" : L"\n");
		}
	}
	fflush(file);
	fclose(file);
	return certCount;
}