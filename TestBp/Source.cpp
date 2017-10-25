#include "stdafx.h"
#include "Windows.h"

typedef NTSTATUS(__fastcall *pMyNtQuerySystemInformation)(
	_In_      ULONG SystemInformationClass,
	_Inout_   PVOID                    SystemInformation,
	_In_      ULONG                    SystemInformationLength,
	_Out_opt_ PULONG                   ReturnLength
	);

typedef NTSTATUS(__fastcall *pNtQueryVirtualMemory)(
	_In_      HANDLE                   ProcessHandle,
	_In_opt_  PVOID                    BaseAddress,
	_In_      ULONG					   MemoryInformationClass,
	_Out_     PVOID                    MemoryInformation,
	_In_      SIZE_T                   MemoryInformationLength,
	_Out_opt_ PSIZE_T                  ReturnLength
	);

pNtQueryVirtualMemory pfn;

int main() 
{ 
	while (true) {
		system("pause");
		for (int i = 0; i < 100; i++)
		{
			__try
			{
				pfn = (pNtQueryVirtualMemory)GetProcAddress(LoadLibrary(L"ntdll.dll"), "NtQueryVirtualMemory");
				if (!pfn)
				{
					printf("error getting func addr");
					break;
				}
				printf("[i: %x] return: %x \r\n", i, pfn(0 , 0, 0, 0, 0,0));
				 
			}
			__except (1)
			{

			}
		}
	}
	system("pause");
	return 0;
}