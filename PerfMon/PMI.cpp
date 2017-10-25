#include <ntddk.h>
#include "PMI.h"
#include "Apic.h"
#include "Common.h"
#include "Log.h"
#include "x86.h"  
#include "ntimage.h"
#include "PMU.h"

extern "C"
{
	//////////////////////////////////////////////////////////////////
	////	Types
	////	 

	typedef enum _MEMORY_INFORMATION_CLASS {
		MemoryBasicInformation
	} MEMORY_INFORMATION_CLASS;


	typedef NTSTATUS (__fastcall *pNtQueryVirtualMemory)(
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
	// The PMI Handler function prototype
	typedef VOID(*PMIHANDLER)(
		_In_ PKTRAP_FRAME TrapFrame
		);

	typedef struct _DRIVER_GLOBAL_DATA {
		BOOLEAN bPtSupported;								// TRUE if Intel PT is supported
		BOOLEAN bPmiInstalled;								// TRUE if I have correctly installed the PMI Handler routine
		BOOLEAN bCpuX2ApicMode;								// TRUE if the system processors are in x2Apic Mode
		BOOLEAN bManualAllocBuff;							// TRUE if the PT buffer has been MANUALLY allocated from User Mode
		ULONG dwNumProcs;									// The number of the system processors
		PDEVICE_OBJECT pMainDev;							// The main device object 
		PMIHANDLER pOldPmiHandler;							// The OLD PMI handler routine (if any)
		TCHAR pmiEventName[0x80];							// The PMI event name shared between user and kernel mode
		PRKEVENT pPmiEvent;									// The PMI event 
		HANDLE hPmiEvent;									// The PMI event kernel handle
		ULONG* lpApicBase;									// The APIC I/O memory VA
		LVT_Entry pmiVectDesc;								// The starting PMI LVT Vector descriptor 
		KAFFINITY kLastCpuAffinity;							// The last trace CPU affinity (used only in user-mode tracing)
		LIST_ENTRY userCallbackList;						// The user callback descriptor list
		KSPIN_LOCK userCallbackListLock;					// The user callback descriptor list spinlock
															//.	PER_PROCESSOR_PT_DATA procData[ANYSIZE_ARRAY];		// An array of PER_PROCESSOR_PT_DATA structure (1 per processor)
															// INTEL_PT_CAPABILITIES ptCapabilities;			// The Intel Processor Trace capabilities (moved to intelpt.h)
															// PKINTERRUPT pkPmiInterrupt = NULL;				// The PMI Interrupt Object (moved to intelpt.h)
	}DRIVER_GLOBAL_DATA, *PDRIVER_GLOBAL_DATA;

#pragma pack(push , 1)
	typedef struct
	{
		UCHAR    FixCode[6];
		ULONG64  JmpAddr;
	}JMPCODE;
#pragma pop()


	//_SYSTEM_SERVICE_TABLE½á¹¹ÉùÃ÷  
	typedef struct _SYSTEM_SERVICE_TABLE {
		PVOID       ServiceTableBase;
		PVOID       ServiceCounterTableBase;
		ULONGLONG   NumberOfServices;
		PVOID       ParamTableBase;
	} SYSTEM_SERVICE_TABLE, *PSYSTEM_SERVICE_TABLE;

	///////////////////////////////////////////////////////////////////////
	//// Global Variable 
	////
	ULONG g_Syscall51Count = 0;
	PVOID g_FakeSsdt = NULL;
	PVOID g_FakeSSsdt = NULL;
	PUCHAR g_ShellCode = NULL;
	ULONG64 g_OrgSsdtOffset = 0;
	ULONG64 g_OrgSssdtOffset = 0;
	pMyNtQuerySystemInformation g_MyNtQuerySystemInformation = NULL;
	pNtQueryVirtualMemory		g_MyNtQueryVirtualMemory = NULL;
	pMyNtCreateFile				g_MyNtCreateFile = NULL;
	DRIVER_GLOBAL_DATA			g_pDrvData = { 0 };
	bool						g_IsUninit = false;
	HASHTABLE					g_inst_table[10000] = { 0 };
	ULONG_PTR					g_InterruptFuncTable[256] = { 0 };
	PUCHAR			 			g_PrivateSsdtTable;
	JMPCODE*					g_JmpCodeTable;
	UCHAR						g_MyServiceSyscallTable[1024];
	UCHAR						g_MyServiceParamTable[1024];
	SYSTEM_SERVICE_TABLE*		g_MyServiceTableDescriptor;

	///////////////////////////////////////////////////////////////////////
	//// Marco
	//// 
	#define SETBIT(x,y) x|=(1<<y)  
	#define CLRBIT(x,y) x&=~(1<<y)  
	#define GETBIT(x,y) (x & (1 << y))  
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
			ServciceAddr   = GetSSDTProcAddress(ServiceTableDescriptor->ServiceTableBase, i, &ParamCount);
			TestRealOffset = GetOffsetAddress((PULONG)ServiceTableDescriptor->ServiceTableBase, (ULONG64)ServciceAddr, (CHAR)ParamCount);
			Offset		   = GetOffsetAddress((PULONG)PrivateServiceTable, (ULONG64)&PrivateHookTable[i], (CHAR)ParamCount);

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
		 
		PrivateSSDT->NumberOfServices		  = ServiceTableDescriptor->NumberOfServices;
		PrivateSSDT->ServiceTableBase		  = PrivateServiceTable;
		PrivateSSDT->ParamTableBase			  = PrivateParamTable;
		PrivateSSDT->ServiceCounterTableBase  = NULL;


		PMU_DEBUG_INFO_LN_EX("ServiceTable: %p ParamTableBase: %p NumOfService: %x ", 
			PrivateSSDT->NumberOfServices,
			PrivateSSDT->ServiceTableBase,
			PrivateSSDT->ParamTableBase
		);

	}

	//--------------------------------------------------------------//
	NTSTATUS SetSyscallProc(ULONG Index , ULONG64 NewAddr, PVOID* OldAddr)
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
	ULONG_PTR GetOriginalSyscallProc(ULONG Index)
	{
		if (!g_ShellCode)
		{
			return 0;
		} 
		return g_JmpCodeTable[Index].JmpAddr;
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
			SYSTEM_SERVICE_TABLE* ssdt = (SYSTEM_SERVICE_TABLE*)g_OrgSsdtOffset;
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
		PMU_DEBUG_INFO_LN_EX("[SSDT NtCreate file] ProcessId: %x FileHandle: %x DesiredAccess: %x ObjectAttributes: %x IoStatusBlock: %x AllocationSize: %x FileAttributes: %x ShareAccess:%x CreateDisposition: %x CreateOptions:%x EaBuffer: %x EaLength: %x" , 
		PsGetCurrentProcessId()	,FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions , EaBuffer, EaLength);

		if (!g_MyNtCreateFile) 
		{ 
			SYSTEM_SERVICE_TABLE* ssdt = (SYSTEM_SERVICE_TABLE*)g_OrgSsdtOffset;
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
			SYSTEM_SERVICE_TABLE* ssdt = (SYSTEM_SERVICE_TABLE*)g_OrgSsdtOffset;
			g_MyNtQuerySystemInformation = (pMyNtQuerySystemInformation)GetSSDTProcAddress(ssdt, 82, NULL);
		}
		return g_MyNtQuerySystemInformation(SystemInformationClass,
			SystemInformation,
			SystemInformationLength,
			ReturnLength
		 );
	}  
	//--------------------------------------------------------------//
	VOID HandleSyscall(PKTRAP_FRAME pTrapFrame)
	{
		ULONG MyOffset = 0;
		UCHAR FixCode[6] = { 0xFF , 0x25 , 0x00 , 0x00 , 0x00 , 0x00 };
		UCHAR Signature[6] = { 0x89 , 0x83, 0xF8 , 0x01 , 0x00 ,0x00 };
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
		
		for (int k = 0; k < 6; k++)
		{
			if (((PUCHAR)pTrapFrame->Rip)[k] != Signature[k])
			{
				return;
			} 
		}
	 
		if (pTrapFrame->Rax == 51 && (PsGetCurrentProcessId() == (HANDLE)15076))
		{
			PMU_DEBUG_INFO_LN_EX("g_Syscall51Count : %x", g_Syscall51Count++); 
		}

		if (pTrapFrame->Rax != 82 && pTrapFrame->Rax != 51 && pTrapFrame->Rax != 32)
		{
			return;
		}

		
		if (!g_ShellCode)
		{
			return;
		}
		
		if (g_PrivateSsdtTable)
		{ 
			PMU_DEBUG_INFO_LN_EX("Hook everything");
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
				if (!g_OrgSsdtOffset)
				{
					g_OrgSsdtOffset = *(PULONG)&g_ShellCode[i + 3]; 
					g_OrgSsdtOffset = (g_OrgSsdtOffset + pTrapFrame->Rip + i + 7);
				}
				
				Ssdt = (SYSTEM_SERVICE_TABLE*)g_OrgSsdtOffset;

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
				PMU_DEBUG_INFO_LN_EX("[Calc2]Verification Result: %p ",(ULONG) (((ULONG64)&g_ShellCode[i] & 0xFFFFFFFF) + MyOffset  + 7));
			 
				*(PULONG)&g_ShellCode[i + 3] = MyOffset;
			
				/*
				for (i = 0; i < 54; i++)
				{
					PMU_DEBUG_INFO_LN_EX("Byte: %X", g_ShellCode[i]);
				}
			   */
				 
				//PMU_DEBUG_INFO_LN_EX("Get My SSDT : %x addr: %p offset: %p  g_MyServiceTableDescriptor: %p ", MyOffset , (ULONG64)&g_ShellCode[i] , (ULONG64)&g_ShellCode[i]+ MyOffset +7, g_MyServiceTableDescriptor);
				

//				SYSTEM_SERVICE_TABLE* SyscallTest = (SYSTEM_SERVICE_TABLE*)(((ULONG64)&g_ShellCode[i] & 0xFFFFFFFF00000000) + ((ULONG)(((ULONG64)&g_ShellCode[i] & 0xFFFFFFFF) + MyOffset + 7)));


//				//PULONG base = (PULONG)SyscallTest->ServiceTableBase;
				//PMU_DEBUG_INFO_LN_EX("[FakeCallTable]SyscallTest:  %p g_MyServiceTableDescriptor: %p", SyscallTest, g_MyServiceTableDescriptor);
				//PMU_DEBUG_INFO_LN_EX("[FakeCallTable]Num: %x Base: %p CountBase: %p", SyscallTest->NumberOfServices, SyscallTest->ServiceTableBase, SyscallTest->ParamTableBase);

				//PMU_DEBUG_INFO_LN_EX("[FakeCallTable2]Num: %x Base: %p CountBase: %p", g_MyServiceTableDescriptor->NumberOfServices, g_MyServiceTableDescriptor->ServiceTableBase, g_MyServiceTableDescriptor->ParamTableBase);
				
				 
				for (i = 0; i < 50 ; i++) {
//					ULONG Count = 0;
//					PVOID Addr = GetSSDTProcAddress(SyscallTest->ServiceTableBase, i, &Count);
				//	PMU_DEBUG_INFO_LN_EX("[FakeCallTable3] %p %p ", Addr, &g_JmpCodeTable[i]);
					for (int j = 0; j < 20; j++)
					{
					//	PMU_DEBUG_INFO_LN_EX("[FakeCallTable3]Processor: %d Bytes %X ", KeGetCurrentProcessorNumber() ,  ((PUCHAR)Addr)[j]);
					}
				 
				}
				PMU_DEBUG_INFO_LN_EX("g_ShellCode: %X ", g_ShellCode);

				SetSyscallProc(51, (ULONG64)MyNtQuerySystemInformation, (PVOID*)&g_MyNtQuerySystemInformation);
				SetSyscallProc(82, (ULONG64)MyNtCreateFile, (PVOID*)&g_MyNtCreateFile);
				SetSyscallProc(32, (ULONG64)MyNtQueryVirtualMemory, (PVOID*)&g_MyNtQueryVirtualMemory);
				 
				pTrapFrame->Rip = (ULONG64)g_ShellCode;

			} 
		} 
		return;
	}
	//--------------------------------------------------------------//
	NTSTATUS DispatchPmiEvent(PKTRAP_FRAME pTrapFrame)
	{
		ULONG64 SystemCall64 = 0;
		NTSTATUS status = STATUS_SUCCESS;
		status = UtilReadMsr(Msr::Ia32Lstar, &SystemCall64);
		if (!NT_SUCCESS(status))
		{
			return status;
		}

		if (pTrapFrame->Rip >= g_InterruptFuncTable[0xE] && pTrapFrame->Rip <= g_InterruptFuncTable[0xE] + 1000)
		{
			//	HandlePageFault(pTrapFrame);
		}

		if (pTrapFrame->Rip >= g_InterruptFuncTable[0x3] && pTrapFrame->Rip <= g_InterruptFuncTable[0x3] + 1000)
		{
			//	HandleBreakpointTrap(pTrapFrame);
		}

		if (pTrapFrame->Rip >= g_InterruptFuncTable[0xD] && pTrapFrame->Rip <= g_InterruptFuncTable[0xD] + 1000)
		{
			//	HandleGeneralProtectException(pTrapFrame);
		}

		if (pTrapFrame->Rip >= SystemCall64 && pTrapFrame->Rip <= SystemCall64 + 1400)
		{
			HandleSyscall(pTrapFrame);
		}

		return status;
	}
	//--------------------------------------------------------------//
	NTSTATUS InitSSDTHook()
	{ 
		g_FakeSsdt = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE * 20, 'ssdt');
		g_FakeSSsdt = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE * 20, 'dsdt');
		g_ShellCode = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, 'cdee');
		g_MyServiceTableDescriptor = (SYSTEM_SERVICE_TABLE*)ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, 'stdt');

		RtlZeroMemory(g_MyServiceTableDescriptor, PAGE_SIZE);
		RtlZeroMemory(g_FakeSsdt, PAGE_SIZE *20);
		RtlZeroMemory(g_FakeSSsdt, PAGE_SIZE*20);
		RtlZeroMemory(g_ShellCode, PAGE_SIZE);
		PMU_DEBUG_INFO_LN_EX("g_MyNtQueryPerformanceCounter: %p", g_MyNtQuerySystemInformation);
		return STATUS_SUCCESS;
	}


	//--------------------------------------------------------------//
	NTSTATUS InitInterrupt()
	{
		IDTDESC info = { 0 };
		PKIDTENTRY64 IdtEntry;
		__sidt(&info);
		IdtEntry = (PKIDTENTRY64)info.BASE;
		for (int i = 0; i < 256; i++)
		{
			ULONG64 handler = 0;
			handler = ((ULONG64)IdtEntry[i].u.OffsetLow | ((ULONG64)IdtEntry[i].u.OffsetMiddle << 16) | ((ULONG64)IdtEntry[i].u.OffsetHigh << 32));
			g_InterruptFuncTable[i] = handler;
			PMU_DEBUG_INFO_LN_EX("Idt[%x]: %p", i, handler);
		}
		return STATUS_SUCCESS;

	}
	//--------------------------------------------------------------//
	NTSTATUS InitApic()
	{
		// First of all we need to search for HalpLocalApic symbol
		MSR_IA32_APIC_BASE_DESC ApicBase = { 0 };				// In Multi-processors systems this address could change
		NTSTATUS status = STATUS_SUCCESS;
		status = UtilReadMsr(Msr::Ia32ApicBase, &ApicBase.All);			// In Windows systems all the processors LVT are mapped at the same physical address

		if (!NT_SUCCESS(status))
		{
			return status;
		}

		if (!ApicBase.Fields.EXTD)
		{
			ULONG* lpdwApicBase = NULL;
			PHYSICAL_ADDRESS apicPhys = { 0 };

			apicPhys.QuadPart = ApicBase.All & (~0xFFFi64);
			lpdwApicBase = (ULONG*)MmMapIoSpace(apicPhys, 0x1000, MmNonCached);

			if (lpdwApicBase)
			{
				DbgPrintEx(0, 0, "[" DRV_NAME "] Successfully mapped the local APIC to 0x%llX.\r\n", lpdwApicBase);
				g_pDrvData.lpApicBase = lpdwApicBase;
			}
			else
			{
				status = STATUS_NOT_SUPPORTED;
				return status;
			}
		}
		else
		{
			// Current system uses x2APIC mode, no need to map anything
			g_pDrvData.bCpuX2ApicMode = TRUE;
		}
		return status;
	}
	//--------------------------------------------------------------//
	NTSTATUS SetUpPerformanceInterrutpHandler(PMIHANDLER Handler)
	{
		PMIHANDLER pNewPmiHandler = Handler;
		NTSTATUS ntStatus = HalSetSystemInformation(HalProfileSourceInterruptHandler, sizeof(PMIHANDLER), (PVOID)&pNewPmiHandler);
		if (NT_SUCCESS(ntStatus))
		{
			DbgPrintEx(0, 0, "[" DRV_NAME "] Successfully registered system PMI handler to function 0x%llX.\r\n", (PVOID)pNewPmiHandler);
		}
		return ntStatus;
	}
	//--------------------------------------------------------------//
	NTSTATUS ResetApic()
	{
		LVT_Entry perfMonDesc = { 0 };
		PULONG lpdwApicBase = g_pDrvData.lpApicBase;
		NTSTATUS status = STATUS_SUCCESS;
		if (g_pDrvData.bCpuX2ApicMode)
		{
			// Check Intel Manuals, Vol. 3A section 10-37
			ULONGLONG perfMonEntry = 0;
			UtilReadMsr(Msr::Ia32x2ApivIvtPmi, &perfMonEntry);
			perfMonDesc.All = (ULONG)perfMonEntry;
			perfMonDesc.Fields.Masked = 0;
			perfMonEntry = (ULONGLONG)perfMonDesc.All;
			UtilWriteMsr(Msr::Ia32x2ApivIvtPmi, perfMonEntry);
		}
		else
		{
			if (!lpdwApicBase)
				// XXX: Not sure how to continue, No MmMapIoSpace at this IRQL (should not happen)
				KeBugCheckEx(INTERRUPT_EXCEPTION_NOT_HANDLED, NULL, NULL, NULL, NULL);

			perfMonDesc.All = lpdwApicBase[0x340 / 4];
			perfMonDesc.Fields.Masked = 0;
			lpdwApicBase[0x340 / 4] = perfMonDesc.All;
		}
		return status;
	}
	//--------------------------------------------------------------//
	VOID IntelPerformanceMonitorInterrupt(PKTRAP_FRAME pTrapFrame)
	{

		START_DO_WHILE

			if (g_IsUninit)
			{
				break;
			}

		//DisablePmi();

		DispatchPmiEvent(pTrapFrame);

		UtilWriteMsr(Msr::Ia32PerfEvtseLx, 0);

		UtilWriteMsr(Msr::Ia32PMCx, (ULONG)0xFFFFFFFE);

		MSR_IA32_PERFEVTSELX_VERSION3 PerfEvtSelx = { 0 };
		PerfEvtSelx.fields.Usr = false;
		PerfEvtSelx.fields.Os = true;
		PerfEvtSelx.fields.E = false;
		PerfEvtSelx.fields.Int = true;
		PerfEvtSelx.fields.CounterMask = 0;
		PerfEvtSelx.fields.En = true;
		PerfEvtSelx.fields.AnyThread = false;
		PerfEvtSelx.fields.EventSelect = 0xC4;
		PerfEvtSelx.fields.UnitMask = 0x40;
		PerfEvtSelx.fields.Inv = false;
		PerfEvtSelx.fields.Pc = false;

		UtilWriteMsr(Msr::Ia32PerfEvtseLx, PerfEvtSelx.all);

		//EnablePmi();

		END_DO_WHILE

			//sth must be done~!
			ResetApic();

		return;
	}
	//--------------------------------------------------------------//
	NTSTATUS RegisterPmiInterrupt()
	{
		NTSTATUS ntStatus = STATUS_SUCCESS;
		ntStatus = InitSSDTHook();
		if (!NT_SUCCESS(ntStatus))
		{
			return ntStatus;
		}
		ntStatus = InitInterrupt();
		if (!NT_SUCCESS(ntStatus))
		{
			return ntStatus;
		}

		ntStatus = InitApic();
		if (!NT_SUCCESS(ntStatus))
		{
			return ntStatus;
		}
		ntStatus = SetUpPerformanceInterrutpHandler(IntelPerformanceMonitorInterrupt);
		if (!NT_SUCCESS(ntStatus))
		{
			return ntStatus;
		}

		return ntStatus;
	}
	//--------------------------------------------------------------//
	// Unregister and remove the LVT PMI interrupt 
	NTSTATUS UnregisterPmiInterrupt()
	{
		NTSTATUS ntStatus = STATUS_SUCCESS;						// Returned NTSTATUS
		PMIHANDLER pOldPmiHandler = g_pDrvData.pOldPmiHandler;	// The old PMI handler

		UtilWriteMsr(Msr::Ia32PerfGlobalCtrl, 0);

		UtilWriteMsr(Msr::Ia32PerfGlobalOvfCtrl, 0);

		UtilWriteMsr(Msr::Ia32PMCx, 0);

		UtilWriteMsr(Msr::Ia32DsArea, 0);

		g_IsUninit = TRUE;

		// This is currently not restoring old PMI handler since we don't know how to retrieve it, just nulling it out
		ntStatus = HalSetSystemInformation(HalProfileSourceInterruptHandler, sizeof(PMIHANDLER), (PVOID)&pOldPmiHandler);

		if (NT_SUCCESS(ntStatus))
		{
			return ntStatus;
		}

		g_pDrvData.bPmiInstalled = FALSE;
		if (g_pDrvData.lpApicBase)
		{
			MmUnmapIoSpace(g_pDrvData.lpApicBase, 0x1000);
		}

		return ntStatus;
	}
}
