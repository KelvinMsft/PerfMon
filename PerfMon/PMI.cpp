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
	 
	///////////////////////////////////////////////////////////////////////
	//// Global Variable 
	////
	
	pMyNtQuerySystemInformation g_MyNtQuerySystemInformation = NULL;
	pNtQueryPerformanceCounter  g_MyNtQueryPerformanceCounter = NULL;
	DRIVER_GLOBAL_DATA			g_pDrvData = { 0 }; 
	bool						g_IsUninit = false; 
	HASHTABLE					g_inst_table[10000] = { 0 }; 
	ULONG_PTR					g_InterruptFuncTable[256] = { 0 };
	  
	//-------------------------------------------------------------------//
	NTSTATUS __fastcall MyNtQuerySystemInformation(
		_In_      ULONG SystemInformationClass,
		_Inout_   PVOID                    SystemInformation,
		_In_      ULONG                    SystemInformationLength,
		_Out_opt_ PULONG                   ReturnLength
	)
	{
		PMU_DEBUG_INFO_LN_EX("g_MyNtQuerySystemInformation : %x \r\n", SystemInformationClass);
		return g_MyNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	}
	//-------------------------------------------------------------------//
	NTSTATUS __fastcall MyNtQueryPerformanceCounter(
		_Out_     PLARGE_INTEGER PerformanceCounter,
		_Out_opt_ PLARGE_INTEGER PerformanceFrequency
	)
	{
		PMU_DEBUG_INFO_LN_EX("NtQueryPerformanceCounter Hook \r\n");
		return g_MyNtQueryPerformanceCounter(PerformanceCounter, PerformanceFrequency);
	}
	//-------------------------------------------------------------------//
	NTSTATUS ResetApic()
	{
		LVT_Entry perfMonDesc = { 0 };
		PULONG lpdwApicBase = g_pDrvData.lpApicBase;
		NTSTATUS status = STATUS_SUCCESS;
		if (g_pDrvData.bCpuX2ApicMode)
		{
			// Check Intel Manuals, Vol. 3A section 10-37
			ULONGLONG perfMonEntry = __readmsr(MSR_IA32_X2APIC_LVT_PMI);
			perfMonDesc.All = (ULONG)perfMonEntry;
			perfMonDesc.Fields.Masked = 0;
			perfMonEntry = (ULONGLONG)perfMonDesc.All;
			__writemsr(MSR_IA32_X2APIC_LVT_PMI, perfMonEntry);
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
	VOID HandlePageFault(PKTRAP_FRAME pTrapFrame)
	{ 
		PMU_DEBUG_INFO_LN_EX("[#PF : %d] cr3: %p pTrapFrame->Rip: %p R10: %I64x Rax: %I64X  sysycalladdr: %p ",
			KeGetCurrentProcessorNumber(), __readcr3(), pTrapFrame->Rip, pTrapFrame->R10, pTrapFrame->Rax, __readmsr(static_cast<ULONG>(Msr::Ia32Lstar))); 
	}

	//--------------------------------------------------------------//
	VOID HandleBreakpointTrap(PKTRAP_FRAME pTrapFrame)
	{  
		PMU_DEBUG_INFO_LN_EX("[#BP : %d] cr3: %p pTrapFrame->Rip: %p R10: %I64x Rax: %I64X  sysycalladdr: %p ",
			KeGetCurrentProcessorNumber(), __readcr3(), pTrapFrame->Rip, pTrapFrame->R10, pTrapFrame->Rax, __readmsr(static_cast<ULONG>(Msr::Ia32Lstar)));

	}	
	//--------------------------------------------------------------//
	VOID HandleGeneralProtectException(PKTRAP_FRAME pTrapFrame)
	{ 
		PMU_DEBUG_INFO_LN_EX("[#GP : %d] cr3: %p pTrapFrame->Rip: %p R10: %I64x Rax: %I64X  sysycalladdr: %p ",
			KeGetCurrentProcessorNumber(), __readcr3(), pTrapFrame->Rip, pTrapFrame->R10, pTrapFrame->Rax, __readmsr(static_cast<ULONG>(Msr::Ia32Lstar)));

	}
	//--------------------------------------------------------------//
	VOID HandleSyscall(PKTRAP_FRAME pTrapFrame)
	{
		ULONG count = 0;
		if (!GetHashIndexById(g_inst_table, 10000, pTrapFrame->Rip, &count))
		{
			PMU_DEBUG_INFO_LN_EX("[syscall/sysenter Cpu No. : %d] cr3: %p pTrapFrame->Rip: %p R10: %I64x Rax: %I64X  sysycalladdr: %p ",
				KeGetCurrentProcessorNumber(), __readcr3(), pTrapFrame->Rip, pTrapFrame->R10, pTrapFrame->Rax, __readmsr(static_cast<ULONG>(Msr::Ia32Lstar)));
			SetHash(g_inst_table, 10000, pTrapFrame->Rip, count++);
		}
		else
		{
			GetHashIndexById(g_inst_table, 10000, pTrapFrame->Rip, &count);
			SetHash(g_inst_table, 10000, pTrapFrame->Rip, count++);
			PMU_DEBUG_INFO_LN_EX("Rip: %p count : %x ", pTrapFrame->Rip, count);
		}

		if (((pTrapFrame->Rip & 0xFFF) == 0xC10) ||
			((pTrapFrame->Rip & 0xFFF) == 0xEA2))
		{

			if (pTrapFrame->R10 == (ULONG64)g_MyNtQuerySystemInformation)
			{
				g_MyNtQuerySystemInformation = (pMyNtQuerySystemInformation)pTrapFrame->R10;
				pTrapFrame->R10 = (ULONG64)MyNtQuerySystemInformation;
				PMU_DEBUG_INFO_LN_EX("[Syscall exploting] NtQueryPerformanceCounter Hook %p ==> %p", g_MyNtQuerySystemInformation, pTrapFrame->R10);
			}
			PMU_DEBUG_INFO_LN_EX("[Syscall exploting] r10: %p g_MyNtQuerySystemInformation: %p Src: %x ", pTrapFrame->R10, g_MyNtQuerySystemInformation, (pTrapFrame->Rip & 0xFFF));
		}
	}
	//--------------------------------------------------------------//
	NTSTATUS DispatchPmiEvent(PKTRAP_FRAME pTrapFrame)
	{
		ULONG64 SystemCall64 = __readmsr(static_cast<ULONG>(Msr::Ia32Lstar));

		if (pTrapFrame->Rip >= g_InterruptFuncTable[0xE] && pTrapFrame->Rip <= g_InterruptFuncTable[0xE] + 1000)
		{
			HandlePageFault(pTrapFrame);
		}

		if (pTrapFrame->Rip >= g_InterruptFuncTable[0x3] && pTrapFrame->Rip <= g_InterruptFuncTable[0x3] + 1000)
		{
			HandleBreakpointTrap(pTrapFrame);
		}

		if (pTrapFrame->Rip >= g_InterruptFuncTable[0xD] && pTrapFrame->Rip <= g_InterruptFuncTable[0xD] + 1000)
		{
			HandleGeneralProtectException(pTrapFrame);
		}

		if (pTrapFrame->Rip >= SystemCall64 && pTrapFrame->Rip <= SystemCall64 + 1400)
		{
			HandleSyscall(pTrapFrame);
		}

		return STATUS_SUCCESS;
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
		
		__writemsr(static_cast<ULONG>(Msr::Ia32PMCx), (ULONG)0xFFFFFFFE);

		MSR_IA32_PERFEVTSELX_VERSION3 PerfEvtSelx = { 0 };
		PerfEvtSelx.fields.Usr = true;
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

		__writemsr(static_cast<ULONG>(Msr::Ia32PerfEvtseLx), PerfEvtSelx.all);

		EnablePmi();
 
		END_DO_WHILE

		//sth must be done~!
		ResetApic();

		return;
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

		PMU_DEBUG_INFO_LN_EX("g_MyNtQueryPerformanceCounter: %p", g_MyNtQuerySystemInformation);
		return STATUS_SUCCESS;
	}

	 
	//--------------------------------------------------------------//
	NTSTATUS InitInterrupt()
	{
		IDTDESC info = { 0 };
		PKIDTENTRY64 IdtEntry ;
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
		ApicBase.All = __readmsr(MSR_IA32_APIC_BASE);			// In Windows systems all the processors LVT are mapped at the same physical address

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
				return STATUS_NOT_SUPPORTED;
			}
		}
		else
		{
			// Current system uses x2APIC mode, no need to map anything
			g_pDrvData.bCpuX2ApicMode = TRUE;
		} 
		return STATUS_SUCCESS;
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

		__writemsr(static_cast<ULONG>(Msr::Ia32PerfGlobalCtrl), 0);

		__writemsr(static_cast<ULONG>(Msr::Ia32PerfGlobalOvfCtrl), 0);

		__writemsr(static_cast<ULONG>(Msr::Ia32PMCx), 0);

		__writemsr(static_cast<ULONG>(Msr::Ia32DsArea), 0);

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