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

	typedef struct _KeShadowTable
	{
		SYSTEM_SERVICE_TABLE NtKernel;
		SYSTEM_SERVICE_TABLE Win32k;
	}TKeShadowTable, *PKeShadowTable;

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
	ULONG						g_SyscallQueryCount = 0;
	ULONG						g_Syscall51Count = 0;
	PVOID						g_FakeSsdt = NULL;
	PVOID						g_FakeSSsdt = NULL;
	PUCHAR						g_ShellCode = NULL;
	ULONG64						g_OrgSsdt = 0;
	ULONG64						g_OrgSSsdt = 0;
	ULONG64						g_OrgSssdtOffset = 0;
	pMyNtQuerySystemInformation g_MyNtQuerySystemInformation = NULL;
	pNtQueryVirtualMemory		g_MyNtQueryVirtualMemory = NULL;
	pMyNtCreateFile				g_MyNtCreateFile = NULL;
	PUCHAR			 			g_PrivateSsdtTable;
	PUCHAR			 			g_PrivateSSsdtTable;
	JMPCODE*					g_JmpCodeTable;
	JMPCODE*					g_ShadowJmpCodeTable;
	UCHAR						g_MyServiceSyscallTable[1024];
	UCHAR						g_MyServiceParamTable[1024];
	UCHAR						g_MyShadowServiceParamTable[1024];
	SYSTEM_SERVICE_TABLE*		g_MyServiceTableDescriptor;


	TKeShadowTable*				g_MyShadowServiceTableDescriptor;
	BOOLEAN						g_IsInit = FALSE;

	ULONG64						g_TargetAddress = NULL;
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


		if (SystemInformationClass == 0x4568)
		{
			PMU_DEBUG_INFO_LN_EX("@@@call count : %u Total: %u", g_SyscallQueryCount , g_Syscall51Count);
			g_SyscallQueryCount = 0;
			g_Syscall51Count = 0;
		}

		if (SystemInformationClass == 0x4567)
		{
			g_SyscallQueryCount++;
			return 0x5678;
		}

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

		//Service table
					/*----------
			  	----- |	Offset |
			----|---- | Offset |
			|	|	  |  ....  |
			|	|	   -----------
			|	|---->| shellCode |
			--------->| shellCode |
					  | ......... |
					   -----------
			*/
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


		PMU_DEBUG_INFO_LN_EX("NumberOfServices: %X ServiceTableBase: %p ParamTableBase: %p ",
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
		BOOLEAN bIsDanger = FALSE;
		 
		if (!g_ShellCode)
		{
			return;
		}

		if (PsGetCurrentProcessId() == (HANDLE)13720)
		{
			if (pTrapFrame->Rax == 51) 
			{
				g_Syscall51Count++;
				PMU_DEBUG_INFO_LN_EX("test flags pro: %d rip: %p rax: %d g_Syscall51Count: %d ", KeGetCurrentProcessorNumber() ,pTrapFrame->Rip, pTrapFrame->Rax, g_Syscall51Count);
			}
		}

		for (int k = 0; k < 6; k++)
		{
			if (((PUCHAR)pTrapFrame->Rip)[k] != Signature[k])
			{
				bIsDanger = TRUE ;
			}
		} 

		for (int i = 0; i < sizeof(g_HookIndex) / sizeof(ULONG); i++)
		{
			if (g_HookIndex[i] == pTrapFrame->Rax)
			{
				IsHooked = TRUE;
			}
		}
		 


		if (g_PrivateSsdtTable)
		{ 
			/*
			.text:000000014006EA90 FB                                      sti
			.text:000000014006EA91 48 89 8B E0 01 00 00                    mov     [rbx+1E0h], rcx
			.text:000000014006EA98 89 83 F8 01 00 00                       mov     [rbx+1F8h], eax 
			*/
			if (!bIsDanger && IsHooked)
			{
				pTrapFrame->Rip = (ULONG64)g_ShellCode;
				return;
			}
			/* 
			.text:000000014006EA9E
			.text:000000014006EA9E                         loc_14006EA9E:                          ; DATA XREF: sub_14006E900+5A¡üo
			.text:000000014006EA9E                                                                 ; .data:00000001401EA838¡ýo
			.text:000000014006EA9E 48 89 A3 D8 01 00 00                    mov     [rbx+1D8h], rsp
			.text:000000014006EAA5 8B F8                                   mov     edi, eax
			.text:000000014006EAA7 C1 EF 07                                shr     edi, 7
			.text:000000014006EAAA 83 E7 20                                and     edi, 20h
			.text:000000014006EAAD 25 FF 0F 00 00                          and     eax, 0FFFh
			.text:000000014006EAB2
			.text:000000014006EAB2                         loc_14006EAB2:                          ; CODE XREF: sub_14006E980+47B¡ýj
			.text:000000014006EAB2 4C 8D 15 47 DE 23 00                    lea     r10, qword_1402AC900
			.text:000000014006EAB9 4C 8D 1D 00 DF 23 00                    lea     r11, byte_1402AC9C0
			*/

			if (pTrapFrame->Rip >= g_TargetAddress - 20 && pTrapFrame->Rip < g_TargetAddress && IsHooked)
			{	
				PMU_DEBUG_INFO_LN_EX("@@@Smaller Case: %p", pTrapFrame->Rip);
				pTrapFrame->Rip = (ULONG64)g_ShellCode;			
				return;
			}
			/*
			.text:000000014006EAB2 4C 8D 15 47 DE 23 00                          lea     r10, qword_1402AC900
			.text:000000014006EAB9 4C 8D 1D 00 DF 23 00                          lea     r11, byte_1402AC9C0
			.text:000000014006EAC0 F7 83 00 01 00 00 80 00 00 00                 test    dword ptr [rbx+100h], 80h
			.text:000000014006EACA 4D 0F 45 D3                                   cmovnz  r10, r11
			.text:000000014006EACE 42 3B 44 17 10                                cmp     eax, [rdi+r10+10h]
			.text:000000014006EAD3 0F 83 E9 02 00 00                             jnb     loc_14006EDC2
			.text:000000014006EAD9 4E 8B 14 17                                   mov     r10, [rdi+r10]
			.text:000000014006EADD 4D 63 1C 82                                   movsxd  r11, dword ptr [r10+rax*4]
			.text:000000014006EAE1 49 8B C3                                      mov     rax, r11						<< + 47
			.text:000000014006EAE4 49 C1 FB 04                                   sar     r11, 4
			*/
			else if ( pTrapFrame->Rip >= g_TargetAddress &&  pTrapFrame->Rip <= g_TargetAddress + 47 && IsHooked)
			{
				PMU_DEBUG_INFO_LN_EX("@@@Middle Case: %p", pTrapFrame->Rip);
				pTrapFrame->Rip = (ULONG64)g_ShellCode + 26;
				
				return;
			} 
			/* 
				.text:000000014006EB40 83 E0 0F                                      and     eax, 0Fh
				.text:000000014006EB43 0F 84 B7 00 00 00                             jz      loc_14006EC00
				.text:000000014006EB49 C1 E0 03                                      shl     eax, 3
				.text:000000014006EB4C 48 8D 64 24 90                                lea     rsp, [rsp-70h]
				.text:000000014006EB51 48 8D 7C 24 18                                lea     rdi, [rsp+70h+var_58]
				.text:000000014006EB56 48 8B B5 00 01 00 00                          mov     rsi, [rbp+100h]
				.text:000000014006EB5D 48 8D 76 20                                   lea     rsi, [rsi+20h]
				.text:000000014006EB61 F6 85 F0 00 00 00 01                          test    byte ptr [rbp+0F0h], 1
				.text:000000014006EB68 74 16                                         jz      short loc_14006EB80
				.text:000000014006EB6A 48 3B 35 8F D4 23 00                          cmp     rsi, cs:MmUserProbeAddress
				.text:000000014006EB71 48 0F 43 35 87 D4 23 00                       cmovnb  rsi, cs:MmUserProbeAddress
				.text:000000014006EB79 0F 1F 80 00 00 00 00                          nop     dword ptr [rax+00000000h]
				.text:000000014006EB80
				.text:000000014006EB80                               loc_14006EB80:                          ; CODE XREF: sub_14006E980+1E8¡üj
				.text:000000014006EB80 4C 8D 1D 79 00 00 00                          lea     r11, loc_14006EC00
				.text:000000014006EB87 4C 2B D8                                      sub     r11, rax
				.text:000000014006EB8A 41 FF E3                                      jmp     r11 
			*/
			else if (pTrapFrame->Rip >= g_TargetAddress + 142 && pTrapFrame->Rip <= g_TargetAddress + 216)
			{
				ULONG64 ProcAddr = 0;
				ULONG   ServiceNum = 0;
				ULONG64 kThread = (ULONG64)KeGetCurrentThread();
				if (!kThread)
					return; 

				ServiceNum = *(PULONG)(kThread + 0x1F8);
				ProcAddr = (ULONG64)GetSSDTProcAddress(g_MyServiceTableDescriptor->ServiceTableBase, ServiceNum, NULL);
				for (int i = 0; i < sizeof(g_HookIndex) / sizeof(ULONG); i++)
				{
					if (g_HookIndex[i] == ServiceNum)
					{
						PMU_DEBUG_INFO_LN_EX("@@@We should record down what is going on here ?? Rip: %p ProcAddr: %p Num: %x ", pTrapFrame->Rip, ProcAddr, ServiceNum);
					}
				} 
				return;
			}   
			else
			{ 
				PMU_DEBUG_INFO_LN_EX("@@PID: %X Uncover Area %p Middle TargetAddress: %p IsHooked: %x", PsGetCurrentProcessId(), pTrapFrame->Rip, g_TargetAddress+47 , IsHooked);
			}

			return;
		}

		RtlZeroMemory(g_ShellCode, PAGE_SIZE);

		ULONG64 RetAddr = pTrapFrame->Rip + 40;
		RtlMoveMemory(g_ShellCode, (PUCHAR)pTrapFrame->Rip, 40);
		RtlCopyMemory(g_ShellCode + 40, FixCode, 6);
		RtlCopyMemory(g_ShellCode + 46, &RetAddr, 8);

		for (int i = 0; i < 40; i++)
		{
		
			if (g_ShellCode[i] == 0x4C && g_ShellCode[i + 1] == 0x8D && g_ShellCode[i + 2] == 0x15)
			{	
				SYSTEM_SERVICE_TABLE* Ssdt = NULL;
				if (!g_OrgSsdt)
				{
					g_OrgSsdt = *(PULONG)&g_ShellCode[i + 3];
					g_OrgSsdt = (g_OrgSsdt + pTrapFrame->Rip + i + 7);
				}
				g_TargetAddress = pTrapFrame->Rip + i;
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
				//SetSyscallProc(82, (ULONG64)MyNtCreateFile, (PVOID*)&g_MyNtCreateFile);
				//SetSyscallProc(32, (ULONG64)MyNtQueryVirtualMemory, (PVOID*)&g_MyNtQueryVirtualMemory);
				///pTrapFrame->Rip = (ULONG64)g_ShellCode;
			}
			
			if (g_ShellCode[i] == 0x4C && g_ShellCode[i + 1] == 0x8D && g_ShellCode[i + 2] == 0x1D)
			{
				SYSTEM_SERVICE_TABLE* SSsdt = NULL;
				if (!g_OrgSSsdt)
				{
					g_OrgSSsdt = *(PULONG)&g_ShellCode[i + 3];
					g_OrgSSsdt = (g_OrgSSsdt + pTrapFrame->Rip + i + 7);
				} 

				SSsdt = ((SYSTEM_SERVICE_TABLE*)g_OrgSSsdt)+1;

				PMU_DEBUG_INFO_LN_EX("Shadow NumberOfServices: %I64x Base: %I64x ", SSsdt->NumberOfServices, SSsdt->ServiceTableBase);

				if (!g_PrivateSSsdtTable)
				{

					g_PrivateSSsdtTable = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, (SSsdt->NumberOfServices * sizeof(JMPCODE)) + (SSsdt->NumberOfServices * sizeof(ULONG)), 'PSSD');
					g_ShadowJmpCodeTable = (JMPCODE*)(g_PrivateSSsdtTable + (SSsdt->NumberOfServices * sizeof(ULONG)));
					if (g_PrivateSSsdtTable)
					{
						RtlZeroMemory((void *)g_PrivateSSsdtTable, (SSsdt->NumberOfServices * sizeof(JMPCODE)) + (SSsdt->NumberOfServices * sizeof(ULONG)));

						BuildPrivateSyscallTable(SSsdt, (PULONG)g_PrivateSSsdtTable, g_MyShadowServiceParamTable, &g_MyShadowServiceTableDescriptor->Win32k, (JMPCODE*)g_ShadowJmpCodeTable);
					}
					else
					{
						PMU_DEBUG_INFO_LN_EX("Break;;;;;;");
						break;
					} 
				}	
				
				memcpy(&g_MyShadowServiceTableDescriptor->NtKernel ,  g_MyServiceTableDescriptor , sizeof(SYSTEM_SERVICE_TABLE));

				MyOffset = (ULONG)(((ULONG64)g_MyShadowServiceTableDescriptor & 0xFFFFFFFF) - ((ULONG64)&g_ShellCode[i] & 0xFFFFFFFF) - 7);
				PMU_DEBUG_INFO_LN_EX("[Calc2]g_MyShadowServiceTableDescriptor: %p g_ShellCode: %p Result: %x ", &g_MyShadowServiceTableDescriptor->Win32k, &g_ShellCode[i], MyOffset);
				PMU_DEBUG_INFO_LN_EX("[Calc2]Verification Result: %p ", (ULONG)(((ULONG64)&g_ShellCode[i] & 0xFFFFFFFF) + MyOffset + 7));
				*(PULONG)&g_ShellCode[i + 3] = MyOffset;

				SYSTEM_SERVICE_TABLE* MySSsdt = (SYSTEM_SERVICE_TABLE*)(((ULONG64)&g_ShellCode[i] & 0xFFFFFFFF00000000) + ((ULONG)(((ULONG64)&g_ShellCode[i] & 0xFFFFFFFF) + MyOffset + 7)));
				PMU_DEBUG_INFO_LN_EX("[FakeCallTable]SyscallTest:  %p g_MyShadowServiceTableDescriptor: %p", MySSsdt, &g_MyShadowServiceTableDescriptor->Win32k);
				PMU_DEBUG_INFO_LN_EX("[FakeCallTable]Num: %x Base: %p CountBase: %p", MySSsdt->NumberOfServices, MySSsdt->ServiceTableBase, MySSsdt->ParamTableBase);
				PMU_DEBUG_INFO_LN_EX("g_ShellCode: %X ", g_ShellCode);
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

		g_MyShadowServiceTableDescriptor = (TKeShadowTable*)ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, 'stdt');
		if (!g_MyShadowServiceTableDescriptor)
		{
			return STATUS_UNSUCCESSFUL;
		}
		RtlZeroMemory(g_MyShadowServiceTableDescriptor, PAGE_SIZE);
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