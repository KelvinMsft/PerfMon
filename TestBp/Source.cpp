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

pMyNtQuerySystemInformation pfn;

int main() 
{ 	
	pfn = (pMyNtQuerySystemInformation)GetProcAddress(LoadLibrary(L"ntdll.dll"), "NtQuerySystemInformation");
	if (!pfn)
	{
		printf("error getting func addr");
		
	}

	while (true) 
	{
		system("pause");
		for (int i = 0; i < 10000; i++)
		{
			__try
			{
			
				printf("[i: %x] return: %x \r\n", i, pfn(0x4567 , 0, 0, 0));
				
			//	DebugBreak();
			}
			__except (1)
			{

			}
		} 
		pfn(0x4568, 0, 0, 0);
	}
	system("pause");
	return 0;
}