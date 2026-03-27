#include <windows.h>
#include <initguid.h>
#include <usbiodef.h>
#include <tlhelp32.h>
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