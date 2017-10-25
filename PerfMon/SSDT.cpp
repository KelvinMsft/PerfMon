#include "SSDT.h"
#include "Log.h"
//////////////////////////////////////////////////////////////////
////	Types
////	 
extern "C" {


	typedef enum _MEMORY_INFORMATION_CLASS {
		MemoryBasicInformation
	} MEMORY_INFORMATION_CLASS;


	typedef NTSTATUS(__fastcall *pNtQueryVirtualMemory)(
		_In_      HANDLE                   ProcessHandle,
		_In_opt_  PVOID                    BaseAddress,
		_In_      MEMORY_INFORMATION_CLASS MemoryInformationClass,
		_Out_     PVOID                    MemoryInformation,
		_In_      SIZE_T                   MemoryInformationLength,
		_Out_opt_ PSIZE_T                  ReturnLength
		);


	typedef NTSTATUS(__fastcall *pNtQueryPerformanceCounter)(
		_Out_     PLARGE_INTEGER PerformanceCounter,
		_Out_opt_ PLARGE_INTEGER PerformanceFrequency
		);

	typedef NTSTATUS(__fastcall *pMyNtQuerySystemInformation)(
		_In_      ULONG SystemInformationClass,
		_Inout_   PVOID                    SystemInformation,
		_In_      ULONG                    SystemInformationLength,
		_Out_opt_ PULONG                   ReturnLength
		);
	typedef NTSTATUS(__fastcall *pMyNtCreateFile)(
		_Out_    PHANDLE            FileHandle,
		_In_     ACCESS_MASK        DesiredAccess,
		_In_     POBJECT_ATTRIBUTES ObjectAttributes,
		_Out_    PIO_STATUS_BLOCK   IoStatusBlock,
		_In_opt_ PLARGE_INTEGER     AllocationSize,
		_In_     ULONG              FileAttributes,
		_In_     ULONG              ShareAccess,
		_In_     ULONG              CreateDisposition,
		_In_     ULONG              CreateOptions,
		_In_     PVOID              EaBuffer,
		_In_     ULONG              EaLength
		);

	///////////////////////////////////////////////////////////////////////
	//// Prototype
	////
	NTSTATUS __fastcall MyNtQuerySystemInformation(
		_In_      ULONG  SystemInformationClass,
		_Inout_   PVOID  SystemInformation,
		_In_      ULONG  SystemInformationLength,
		_Out_opt_ PULONG ReturnLength
	);
	NTSTATUS __fastcall MyNtCreateFile(
		_Out_    PHANDLE            FileHandle,
		_In_     ACCESS_MASK        DesiredAccess,
		_In_     POBJECT_ATTRIBUTES ObjectAttributes,
		_Out_    PIO_STATUS_BLOCK   IoStatusBlock,
		_In_opt_ PLARGE_INTEGER     AllocationSize,
		_In_     ULONG              FileAttributes,
		_In_     ULONG              ShareAccess,
		_In_     ULONG              CreateDisposition,
		_In_     ULONG              CreateOptions,
		_In_     PVOID              EaBuffer,
		_In_     ULONG              EaLength
	);

	NTSTATUS __fastcall MyNtQueryVirtualMemory(
		_In_      HANDLE                   ProcessHandle,
		_In_opt_  PVOID                    BaseAddress,
		_In_      MEMORY_INFORMATION_CLASS MemoryInformationClass,
		_Out_     PVOID                    MemoryInformation,
		_In_      SIZE_T                   MemoryInformationLength,
		_Out_opt_ PSIZE_T                  ReturnLength
	);
	///////////////////////////////////////////////////////////////////////
	//// Marco
	//// 
	#define NtQueryVirtualMemServiceNumber	32
	#define NtQuerySysInfoServiceNumber		51
	#define NtCreateFileServiceNumber		82 
	#define SETBIT(x,y) x|=(1<<y)  
	#define CLRBIT(x,y) x&=~(1<<y)  
	#define GETBIT(x,y) (x & (1 << y)) 

	
	///////////////////////////////////////////////////////////////////////
	//// Global Variable 
	////

	ULONG						g_Syscall51Count = 0;
	PVOID						g_FakeSsdt = NULL;
	PVOID						g_FakeSSsdt = NULL;
	PUCHAR						g_ShellCode = NULL;
	ULONG64						g_OrgSsdt = 0;
	ULONG64						g_OrgSssdtOffset = 0;
	pMyNtQuerySystemInformation g_MyNtQuerySystemInformation = NULL;
	pNtQueryVirtualMemory		g_MyNtQueryVirtualMemory = NULL;
	pMyNtCreateFile				g_MyNtCreateFile = NULL;
	PUCHAR			 			g_PrivateSsdtTable;
	JMPCODE*					g_JmpCodeTable;
	UCHAR						g_MyServiceSyscallTable[1024];
	UCHAR						g_MyServiceParamTable[1024];
	SYSTEM_SERVICE_TABLE*		g_MyServiceTableDescriptor;
	BOOLEAN						g_IsInit = FALSE;

	
	ULONG						g_HookIndex[] = { NtQueryVirtualMemServiceNumber , NtQuerySysInfoServiceNumber , NtCreateFileServiceNumber };
 
//--------------------------------------------------------------//
	NTSTATUS SetSyscallProc(ULONG Index, ULONG64 NewAddr, PVOID* OldAddr)
	{
		NTSTATUS status = STATUS_SUCCESS;
		if (!g_ShellCode)
		{
			status = STATUS_UNSUCCESSFUL;
			return status;
		}

		if (OldAddr)
		{
			*OldAddr = (VOID*)g_JmpCodeTable[Index].JmpAddr;
		}

		g_JmpCodeTable[Index].JmpAddr = NewAddr;
		return status;
	}

	//--------------------------------------------------------------//
	NTSTATUS __fastcall MyNtQueryVirtualMemory(
		_In_      HANDLE                   ProcessHandle,
		_In_opt_  PVOID                    BaseAddress,
		_In_      MEMORY_INFORMATION_CLASS MemoryInformationClass,
		_Out_     PVOID                    MemoryInformation,
		_In_      SIZE_T                   MemoryInformationLength,
		_Out_opt_ PSIZE_T                  ReturnLength
	)
	{
		PMU_DEBUG_INFO_LN_EX("[SSDT NtQueryVirtualMemory] ProcessId: %x ProcessHandle: %x BaseAddress: %x MemoryInformationClass: %x MemoryInformation: %x MemoryInformationLength: %x ReturnLength: %x",
			PsGetCurrentProcessId(), ProcessHandle,
			BaseAddress,
			MemoryInformationClass,
			MemoryInformation,
			MemoryInformationLength,
			ReturnLength);

		if (!g_MyNtQueryVirtualMemory)
		{
			SYSTEM_SERVICE_TABLE* ssdt = (SYSTEM_SERVICE_TABLE*)g_OrgSsdt;
			g_MyNtQueryVirtualMemory = (pNtQueryVirtualMemory)GetSSDTProcAddress(ssdt, 82, NULL);
		}
		return g_MyNtQueryVirtualMemory(
			ProcessHandle,
			BaseAddress,
			MemoryInformationClass,
			MemoryInformation,
			MemoryInformationLength,
			ReturnLength);
	}



	//--------------------------------------------------------------//
	NTSTATUS __fastcall MyNtCreateFile(
		_Out_    PHANDLE            FileHandle,
		_In_     ACCESS_MASK        DesiredAccess,
		_In_     POBJECT_ATTRIBUTES ObjectAttributes,
		_Out_    PIO_STATUS_BLOCK   IoStatusBlock,
		_In_opt_ PLARGE_INTEGER     AllocationSize,
		_In_     ULONG              FileAttributes,
		_In_     ULONG              ShareAccess,
		_In_     ULONG              CreateDisposition,
		_In_     ULONG              CreateOptions,
		_In_     PVOID              EaBuffer,
		_In_     ULONG              EaLength
	)
	{
		PMU_DEBUG_INFO_LN_EX("[SSDT NtCreate file] ProcessId: %x FileHandle: %x DesiredAccess: %x ObjectAttributes: %x IoStatusBlock: %x AllocationSize: %x FileAttributes: %x ShareAccess:%x CreateDisposition: %x CreateOptions:%x EaBuffer: %x EaLength: %x",
			PsGetCurrentProcessId(), FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);

		if (!g_MyNtCreateFile)
		{
			SYSTEM_SERVICE_TABLE* ssdt = (SYSTEM_SERVICE_TABLE*)g_OrgSsdt;
			g_MyNtCreateFile = (pMyNtCreateFile)GetSSDTProcAddress(ssdt, 82, NULL);
		}
		return g_MyNtCreateFile(
			FileHandle,
			DesiredAccess,
			ObjectAttributes,
			IoStatusBlock,
			AllocationSize,
			FileAttributes,
			ShareAccess,
			CreateDisposition,
			CreateOptions,
			EaBuffer,
			EaLength);
	}
	//--------------------------------------------------------------//
	NTSTATUS __fastcall MyNtQuerySystemInformation(
		_In_      ULONG  SystemInformationClass,
		_Inout_   PVOID  SystemInformation,
		_In_      ULONG  SystemInformationLength,
		_Out_opt_ PULONG ReturnLength
	)
	{

		PMU_DEBUG_INFO_LN_EX("[SSDT NtQuerySystemInformation] Core: %x ProcessId: %x SystemInformationClass: %X SystemInformationLength: %X ReturnLength: %X ",
			KeGetCurrentProcessorNumber(), PsGetCurrentProcessId(), SystemInformationClass,
			SystemInformation,
			SystemInformationLength,
			ReturnLength);

		if (!g_MyNtQuerySystemInformation)
		{
			SYSTEM_SERVICE_TABLE* ssdt = (SYSTEM_SERVICE_TABLE*)g_OrgSsdt;
			g_MyNtQuerySystemInformation = (pMyNtQuerySystemInformation)GetSSDTProcAddress(ssdt, 82, NULL);
		}
		return g_MyNtQuerySystemInformation(SystemInformationClass,
			SystemInformation,
			SystemInformationLength,
			ReturnLength
		);
	}
	//-------------------------------------------------------------------------------------------------------------
	VOID BuildPrivateSyscallTable(
		_In_  SYSTEM_SERVICE_TABLE* ServiceTableDescriptor,
		_In_  PULONG				PrivateServiceTable,
		_In_  UCHAR*				PrivateParamTable,
		_Out_ SYSTEM_SERVICE_TABLE* PrivateSSDT,
		_In_  JMPCODE*				PrivateHookTable)
	{
		int i = 0;
		UCHAR FixCode[6] = { 0xFF , 0x25 , 0x00 , 0x00 , 0x00 , 0x00 };
		ULONG ParamCount = 0;
		PVOID ServciceAddr = NULL;
		ULONG TestRealOffset = 0;
		ULONG Offset = 0;

		if (!ServiceTableDescriptor || !PrivateParamTable || !PrivateSSDT)
		{
			return;
		}

		memcpy(PrivateParamTable, ServiceTableDescriptor->ParamTableBase, ServiceTableDescriptor->NumberOfServices);

		for (i = 0; i < ServiceTableDescriptor->NumberOfServices; ++i)
		{
			ServciceAddr = GetSSDTProcAddress(ServiceTableDescriptor->ServiceTableBase, i, &ParamCount);
			TestRealOffset = GetOffsetAddress((PULONG)ServiceTableDescriptor->ServiceTableBase, (ULONG64)ServciceAddr, (CHAR)ParamCount);
			Offset = GetOffsetAddress((PULONG)PrivateServiceTable, (ULONG64)&PrivateHookTable[i], (CHAR)ParamCount);

			PrivateServiceTable[i] = Offset;
			RtlCopyMemory(&PrivateHookTable[i].FixCode, FixCode, 6);
			PrivateHookTable[i].JmpAddr = (ULONG64)ServciceAddr;

			PMU_DEBUG_INFO_LN_EX(" SSDT Proc: %p TestRealOffset: %x realoffset:%x MyOffset: %x g_PrivateSsdtTable: %p g_JmpCodeTable: %p ParamCount: %x HookTable: %p",
				ServciceAddr,
				TestRealOffset,
				*(PULONG)((ULONG64)ServiceTableDescriptor->ServiceTableBase + i * 4),
				Offset,
				g_PrivateSsdtTable,
				g_JmpCodeTable,
				PrivateParamTable[i],
				PrivateHookTable
			);
		}

		PrivateSSDT->NumberOfServices = ServiceTableDescriptor->NumberOfServices;
		PrivateSSDT->ServiceTableBase = PrivateServiceTable;
		PrivateSSDT->ParamTableBase = PrivateParamTable;
		PrivateSSDT->ServiceCounterTableBase = NULL;


		PMU_DEBUG_INFO_LN_EX("ServiceTable: %p ParamTableBase: %p NumOfService: %x ",
			PrivateSSDT->NumberOfServices,
			PrivateSSDT->ServiceTableBase,
			PrivateSSDT->ParamTableBase
		);

	}

	//-------------------------------------------------------------------------------------------------------------
	ULONG GetOffsetAddress(PULONG SSDTBase, ULONGLONG FuncAddr, CHAR paramCount)
	{
		ULONG dwtmp = 0, i;
		CHAR b = 0, bits[4] = { 0 };
		PULONG stb = NULL;
		stb = SSDTBase;
		dwtmp = (ULONG)(FuncAddr - (ULONGLONG)stb);
		dwtmp = dwtmp << 4;

		memcpy(&b, &dwtmp, 1);
		for (i = 0; i < 4; i++)
		{
			bits[i] = GETBIT(paramCount, i);
			if (bits[i])
			{
				SETBIT(b, i);
			}
			else
			{
				CLRBIT(b, i);
			}
		}
		memcpy(&dwtmp, &b, 1);
		return (ULONG)dwtmp;
	}
	//-------------------------------------------------------------------------------------------------------------
	void* GetSSDTProcAddress(void* SSTD, ULONG Index, PULONG lpParamCount)
	{
		ULONG* Table = NULL;
		ULONG  Offset;
		ULONGLONG Offset_U;

		if (!SSTD || Index == -1)
		{
			return NULL;
		}
		Table = (ULONG*)(SSTD);
		Offset = Table[Index];
		if (Offset & 0x80000000)
		{
			Offset_U = 0xfffffffff0000000 + (Offset >> 4);
		}
		else
		{
			Offset_U = (Offset >> 4);
		}

		if (lpParamCount)
		{
			*lpParamCount = Offset & 0x0000000F;
		}

		return (PCHAR)Table + Offset_U;
	}

	//-------------------------------------------------------------------------------------------------------------
	VOID SyscallHandler(PKTRAP_FRAME pTrapFrame)
	{		
		/*
		*
			.text:000000014006EA90 FB                                      sti
			.text:000000014006EA91 48 89 8B E0 01 00 00                    mov     [rbx+1E0h], rcx
			.text:000000014006EA98 89 83 F8 01 00 00                       mov     [rbx+1F8h], eax				<<<< Interrupt here
			.text:000000014006EA9E
			.text:000000014006EA9E                         KiSystemServiceStart:                   ; DATA XREF: KiServiceInternal+5A¡üo
			.text:000000014006EA9E                                                                 ; .data:00000001401EA838¡ýo
			.text:000000014006EA9E 48 89 A3 D8 01 00 00                    mov     [rbx+1D8h], rsp
			.text:000000014006EAA5 8B F8                                   mov     edi, eax
			.text:000000014006EAA7 C1 EF 07                                shr     edi, 7
			.text:000000014006EAAA 83 E7 20                                and     edi, 20h
			.text:000000014006EAAD 25 FF 0F 00 00                          and     eax, 0FFFh
			.text:000000014006EAB2
			.text:000000014006EAB2                         KiSystemServiceRepeat:                  ; CODE XREF: KiSystemCall64+47B¡ýj
			.text:000000014006EAB2 4C 8D 15 47 DE 23 00                    lea     r10, KeServiceDescriptorTable
			.text:000000014006EAB9 4C 8D 1D 00 DF 23 00                    lea     r11, KeServiceDescriptorTableShadow
			.text:000000014006EAC0 F7 83 00 01 00 00 80 00+                test    dword ptr [rbx+100h], 80h	<<<< after interrupt
		*/ 
		ULONG MyOffset = 0;
		UCHAR FixCode[6] = { 0xFF , 0x25 , 0x00 , 0x00 , 0x00 , 0x00 };
		UCHAR Signature[6] = { 0x89 , 0x83, 0xF8 , 0x01 , 0x00 ,0x00 };
		BOOLEAN  IsHooked = FALSE;
		for (int k = 0; k < 6; k++)
		{
			if (((PUCHAR)pTrapFrame->Rip)[k] != Signature[k])
			{
				return;
			}
		}
		  
		for (int k = 0; k < sizeof(g_HookIndex) ; k++)
		{
			if (pTrapFrame->Rax == g_HookIndex[k])
			{
				IsHooked = TRUE;
			}
		}

		if (!IsHooked)
		{
			return; 
		}

		if (!g_ShellCode)
		{
			return;
		}

		if (g_PrivateSsdtTable)
		{ 
			pTrapFrame->Rip = (ULONG64)g_ShellCode;
			return;
		}

		RtlZeroMemory(g_ShellCode, PAGE_SIZE);

		ULONG64 RetAddr = pTrapFrame->Rip + 33;
		RtlMoveMemory(g_ShellCode, (PUCHAR)pTrapFrame->Rip, 33);
		RtlCopyMemory(g_ShellCode + 33, FixCode, 6);
		RtlCopyMemory(g_ShellCode + 39, &RetAddr, 8);

		for (int i = 0; i < 33; i++)
		{
			SYSTEM_SERVICE_TABLE* Ssdt = NULL;
			if (g_ShellCode[i] == 0x4C && g_ShellCode[i + 1] == 0x8D && g_ShellCode[i + 2] == 0x15)
			{
				if (!g_OrgSsdt)
				{
					g_OrgSsdt = *(PULONG)&g_ShellCode[i + 3];
					g_OrgSsdt = (g_OrgSsdt + pTrapFrame->Rip + i + 7);
				}

				Ssdt = (SYSTEM_SERVICE_TABLE*)g_OrgSsdt;

				PMU_DEBUG_INFO_LN_EX(" NumberOfServices: %I64x Base: %I64x ", Ssdt->NumberOfServices, Ssdt->ServiceTableBase);

				if (!g_PrivateSsdtTable)
				{
					g_PrivateSsdtTable = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, (Ssdt->NumberOfServices * sizeof(JMPCODE)) + (Ssdt->NumberOfServices * sizeof(ULONG)), 'PSSD');
					g_JmpCodeTable = (JMPCODE*)(g_PrivateSsdtTable + (Ssdt->NumberOfServices * sizeof(ULONG)));
					if (g_PrivateSsdtTable)
					{
						RtlZeroMemory((void *)g_PrivateSsdtTable, (Ssdt->NumberOfServices * sizeof(JMPCODE)) + (Ssdt->NumberOfServices * sizeof(ULONG)));

						BuildPrivateSyscallTable(Ssdt, (PULONG)g_PrivateSsdtTable, g_MyServiceParamTable, g_MyServiceTableDescriptor, (JMPCODE*)g_JmpCodeTable);
					}
					else
					{
						PMU_DEBUG_INFO_LN_EX("Break;;;;;;");
						break;
					}
				}


				MyOffset = (ULONG)(((ULONG64)g_MyServiceTableDescriptor & 0xFFFFFFFF) - ((ULONG64)&g_ShellCode[i] & 0xFFFFFFFF) - 7);
				PMU_DEBUG_INFO_LN_EX("[Calc2]g_MyServiceTableDescriptor: %p g_ShellCode: %p Result: %x ", g_MyServiceTableDescriptor, &g_ShellCode[i], MyOffset);
				PMU_DEBUG_INFO_LN_EX("[Calc2]Verification Result: %p ", (ULONG)(((ULONG64)&g_ShellCode[i] & 0xFFFFFFFF) + MyOffset + 7));

				// 	.text:000000014006EAB2 4C 8D 15 47 DE 23 00                    lea     r10, KeServiceDescriptorTable
				// put our offset on the lea instruction 
				*(PULONG)&g_ShellCode[i + 3] = MyOffset;
				  
				//we only need calculate low 32bit , if the offset < 0 , it will overflow for bit 33 , we dun need it ~  
				SYSTEM_SERVICE_TABLE* MySsdt = (SYSTEM_SERVICE_TABLE*)(((ULONG64)&g_ShellCode[i] & 0xFFFFFFFF00000000) + ((ULONG)(((ULONG64)&g_ShellCode[i] & 0xFFFFFFFF) + MyOffset + 7)));

				PMU_DEBUG_INFO_LN_EX("[FakeCallTable]SyscallTest:  %p g_MyServiceTableDescriptor: %p", MySsdt, g_MyServiceTableDescriptor);
				PMU_DEBUG_INFO_LN_EX("[FakeCallTable]Num: %x Base: %p CountBase: %p", MySsdt->NumberOfServices, MySsdt->ServiceTableBase, MySsdt->ParamTableBase);   
				PMU_DEBUG_INFO_LN_EX("g_ShellCode: %X ", g_ShellCode);

				SetSyscallProc(51, (ULONG64)MyNtQuerySystemInformation, (PVOID*)&g_MyNtQuerySystemInformation);
				SetSyscallProc(82, (ULONG64)MyNtCreateFile, (PVOID*)&g_MyNtCreateFile);
				SetSyscallProc(32, (ULONG64)MyNtQueryVirtualMemory, (PVOID*)&g_MyNtQueryVirtualMemory);

				pTrapFrame->Rip = (ULONG64)g_ShellCode;

			}
		}
	}


	//--------------------------------------------------------------//
	NTSTATUS InitSSDTHook()
	{

		g_FakeSsdt = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE * 20, 'ssdt');
		if (!g_FakeSsdt)
		{
			return STATUS_UNSUCCESSFUL;
		} 

		g_ShellCode = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, 'cdee');
		if (!g_ShellCode)
		{
			return STATUS_UNSUCCESSFUL;
		}
		
		g_MyServiceTableDescriptor = (SYSTEM_SERVICE_TABLE*)ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, 'stdt');
		if (!g_MyServiceTableDescriptor)
		{
			return STATUS_UNSUCCESSFUL;
		}

		RtlZeroMemory(g_MyServiceTableDescriptor, PAGE_SIZE);
		RtlZeroMemory(g_FakeSsdt, PAGE_SIZE * 20); 
		RtlZeroMemory(g_ShellCode, PAGE_SIZE); 

		g_IsInit = TRUE;

		return STATUS_SUCCESS;
	}
	//--------------------------------------------------------------//
	NTSTATUS UninitSSDTHook()
	{
		g_IsInit = FALSE;
		if (!g_FakeSsdt)
		{
			ExFreePool(g_FakeSsdt);
			g_FakeSsdt = NULL;
		}

		if (!g_FakeSSsdt)
		{
			ExFreePool(g_FakeSSsdt);
			g_FakeSSsdt = NULL;
		}

		if (!g_ShellCode)
		{
			ExFreePool(g_ShellCode);
			g_ShellCode = NULL;
		}
		return STATUS_SUCCESS;
	}
}