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

	typedef struct
	{
		UCHAR    FixCode[6];
		ULONG64 JmpAddr;
	}JMPCODE;


	//_SYSTEM_SERVICE_TABLE结构声明  
	typedef struct _SYSTEM_SERVICE_TABLE {
		PVOID       ServiceTableBase;
		PVOID       ServiceCounterTableBase;
		ULONGLONG   NumberOfServices;
		PVOID       ParamTableBase;
	} SYSTEM_SERVICE_TABLE, *PSYSTEM_SERVICE_TABLE;

	///////////////////////////////////////////////////////////////////////
	//// Global Variable 
	////
	PVOID g_FakeSsdt = NULL;
	PVOID g_FakeSSsdt = NULL;
	PUCHAR g_ShellCode = NULL;
	ULONG64 g_OrgSsdtOffset = 0;
	ULONG64 g_OrgSssdtOffset = 0;
	pMyNtQuerySystemInformation g_MyNtQuerySystemInformation = NULL;
	pNtQueryPerformanceCounter  g_MyNtQueryPerformanceCounter = NULL;
	DRIVER_GLOBAL_DATA			g_pDrvData = { 0 };
	bool						g_IsUninit = false;
	HASHTABLE					g_inst_table[10000] = { 0 };
	ULONG_PTR					g_InterruptFuncTable[256] = { 0 };
	PUCHAR			 			g_PrivateSsdtTable;
	JMPCODE*					g_JmpCodeTable;
	//设置函数的偏移地址，注意其中参数的处理。低四位放了参数个数减4个参数。如果参数小于等于4的时候为0  
#define SETBIT(x,y) x|=(1<<y) //将X的第Y位置1  
#define CLRBIT(x,y) x&=~(1<<y) //将X的第Y位清0  
#define GETBIT(x,y) (x & (1 << y)) //取X的第Y位，返回0或非0  
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

		//--------------------------------------------------------------//
		VOID HandleSyscall(PKTRAP_FRAME pTrapFrame)
		{
			if (pTrapFrame->Rax == 82)
			{

				if ((pTrapFrame->Rip & 0xFFF) == 0xA98)
				{
					PMU_DEBUG_INFO_LN_EX("Processor: %d Irql: %d NtCreateFile: Rip: %p", KeGetCurrentProcessorNumber(), KeGetCurrentIrql(), pTrapFrame->Rip);
					if (g_ShellCode && !g_OrgSsdtOffset & !g_OrgSssdtOffset)
					{
						UCHAR FixCode[6] = { 0xFF , 0x25 , 0x00 , 0x00 , 0x00 , 0x00 };
						ULONG ParamCount = 0;
						RtlMoveMemory(g_ShellCode, (PUCHAR)pTrapFrame->Rip, 40);
						for (int i = 0; i < 40; i++)
						{
							PMU_COMMON_DEBUG_INFO("%X", g_ShellCode[i]);
							if (g_ShellCode[i] == 0x4C && g_ShellCode[i + 1] == 0x8D)
							{
								if (g_ShellCode[i + 2] == 0x15)
								{
									g_OrgSsdtOffset = *(PULONG)&g_ShellCode[i + 3];
									
									if (g_OrgSsdtOffset)
									{
										SYSTEM_SERVICE_TABLE* Ssdt = (SYSTEM_SERVICE_TABLE*)(g_OrgSsdtOffset + pTrapFrame->Rip + i + 7);

										PMU_DEBUG_INFO_LN_EX(" NumberOfServices: %I64x Base: %I64x ", Ssdt->NumberOfServices, Ssdt->ServiceTableBase);

										g_PrivateSsdtTable = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, (Ssdt->NumberOfServices * sizeof(JMPCODE)) + (Ssdt->NumberOfServices * sizeof(ULONG)), 'PSSD');
										if (!g_PrivateSsdtTable)
										{
											break;
										}
										RtlZeroMemory((void *)g_PrivateSsdtTable,  (Ssdt->NumberOfServices * sizeof(JMPCODE)) + (Ssdt->NumberOfServices * sizeof(ULONG))); 
										g_JmpCodeTable = (JMPCODE*)(g_PrivateSsdtTable + (Ssdt->NumberOfServices * sizeof(ULONG)));
										for (i = 0; (unsigned __int64)i < Ssdt->NumberOfServices; ++i)
										{ 
											PVOID ServciceAddr   = GetSSDTProcAddress(Ssdt->ServiceTableBase, i, &ParamCount);
											ULONG TestRealOffset = GetOffsetAddress((PULONG)Ssdt->ServiceTableBase, (ULONG64)ServciceAddr, (CHAR)ParamCount);
											ULONG Offset = GetOffsetAddress((PULONG)g_PrivateSsdtTable, (ULONG64)&g_JmpCodeTable[i],(CHAR)ParamCount);
											*(PULONG)&g_PrivateSsdtTable[i] = Offset;
											RtlCopyMemory(&g_JmpCodeTable[i].FixCode, FixCode, 6);
											RtlCopyMemory(&g_JmpCodeTable[i].JmpAddr, &ServciceAddr, 8);
											PMU_DEBUG_INFO_LN_EX(" SSDT Proc: %p TestRealOffset: %x realoffset:%x MyOffset: %x g_PrivateSsdtTable: %p g_JmpCodeTable: %p",
												ServciceAddr,
												TestRealOffset,
												*(PULONG)((ULONG64)Ssdt->ServiceTableBase + i * 4),
												Offset,										 
												g_PrivateSsdtTable,
												g_JmpCodeTable
											); 
										}

									}
									 
									g_OrgSsdtOffset = pTrapFrame->Rip + g_OrgSsdtOffset + 7;
									ULONG64 RetAddr = pTrapFrame->Rip + 40;
									RtlCopyMemory((char *)g_ShellCode + 40, FixCode, 6);
									RtlCopyMemory((char *)g_ShellCode + 46, &RetAddr , 8);   
									//pTrapFrame->Rip  = (ULONG64)g_ShellCode;

								}
								else if(g_ShellCode[i + 2] == 0x1D)
								{
									g_OrgSssdtOffset = *(PULONG)&g_ShellCode[i + 3];
									g_OrgSssdtOffset = pTrapFrame->Rip + g_OrgSssdtOffset + 7;
								}
							}
						}
						PMU_DEBUG_INFO_LN_EX("");
						PMU_DEBUG_INFO_LN_EX("g_OrgSsdtOffset: %p g_OrgSssdtOffset: %p", g_OrgSsdtOffset, g_OrgSssdtOffset);

					

					}
				}
			}
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

			g_MyNtQuerySystemInformation = (pMyNtQuerySystemInformation)UtilGetSystemProcAddress(L"NtQuerySystemInformation");

			if (!g_MyNtQuerySystemInformation)
			{
				PMU_DEBUG_INFO_LN_EX("[FATAL] : %p ", g_MyNtQuerySystemInformation);
				return STATUS_UNSUCCESSFUL;
			}

			g_FakeSsdt = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE * 20, 'ssdt');
			g_FakeSSsdt = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE * 20, 'dsdt');
			g_ShellCode = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, 'cdee');

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

			DisablePmi();

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

			EnablePmi();

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
