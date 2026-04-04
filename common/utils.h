#include <windows.h>
#include <initguid.h>
#include <usbiodef.h>
#include <tlhelp32.h>
#define WINDOWS_TITLE_1 L"\u0411\u0435\u0437\u043e\u043f\u0430\u0441\u043d\u043e\u0441\u0442\u044c Windows"
#define WINDOWS_TITLE_2 L"Безопасность Windows"

#define AVEST_TITLE_1 L"Avest CSP Bel Pro x64 - \u043a\u043e\u043d\u0442\u0435\u0439\u043d\u0435\u0440 \u043b\u0438\u0447\u043d\u044b\u0445 \u043a\u043b\u044e\u0447\u0435\u0439"
#define AVEST_TITLE_2 L"Avest CSP Bel Pro x64 - контейнер личных ключей"
typedef struct _CertData {
	char Serial[64];
	wchar_t ContainerName[128];
	wchar_t USBSerial[32];
	wchar_t password[32];
} CertData, * PCertData;
#define SERIAL_MAX_SIZE  128
DWORD GetProcessIdByName(const wchar_t* processName);
PCCERT_CONTEXT findCertContext(wchar_t* containerName, char* serial);
void readMyCerificates(PCertData certs, int* count);
void getPluggedUSBSerialNumbers(PCertData certs, int* count);
int ReadSavedFile(PCertData* outArray, int* outCount);
int WriteSavedFile(PCertData certArray, int certCount);
int usb_serial_cmp(wchar_t* serial1, wchar_t* serial2);
PCertData findCertDataByUSBSerialAndContainerName(PCertData certs, int count, wchar_t* usbSerial, wchar_t* containerName);
PCertData findSavedCertDataByUSBSerial(wchar_t* usbSerial);
BOOL IsCertificateDateValid(FILETIME ftNotBefore, FILETIME ftNotAfter);
char* getCertSerialByContainerName(wchar_t* containerName);