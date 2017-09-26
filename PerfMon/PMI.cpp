#include <ntddk.h>
#include "PMI.h"
#include "Apic.h"
#include "Common.h"
#include "Log.h"
#include "x86.h"
#include "..\capstone\include\capstone.h"
#include "asm.h"
#include "LDasm.h"
extern "C"
{
	//////////////////////////////////////////////////////////////////
	////	Types
	////	 

	// The PMI Handler function prototype
	typedef VOID(*PMIHANDLER)(PKTRAP_FRAME TrapFrame);

	// The custom PMI ISR routines
	typedef VOID(*INTELPT_PMI_HANDLER)(ULONG dwCpuId, PVOID ptBuffDesc);


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
		INTELPT_PMI_HANDLER pCustomPmiIsr;					// The registered custom Kernel-Mode PMI Isr routine (if any)
		KAFFINITY kLastCpuAffinity;							// The last trace CPU affinity (used only in user-mode tracing)
		LIST_ENTRY userCallbackList;						// The user callback descriptor list
		KSPIN_LOCK userCallbackListLock;					// The user callback descriptor list spinlock
															//.	PER_PROCESSOR_PT_DATA procData[ANYSIZE_ARRAY];		// An array of PER_PROCESSOR_PT_DATA structure (1 per processor)
															// INTEL_PT_CAPABILITIES ptCapabilities;			// The Intel Processor Trace capabilities (moved to intelpt.h)
															// PKINTERRUPT pkPmiInterrupt = NULL;				// The PMI Interrupt Object (moved to intelpt.h)
	}DRIVER_GLOBAL_DATA, *PDRIVER_GLOBAL_DATA;


	DRIVER_GLOBAL_DATA g_pDrvData;
	extern void* g_out;
	extern debug_store g_ds[8];
	extern ULONG pebs_record_size;

	ULONG g_printCount = 0;
	bool g_IsUninit = false;

	HASHTABLE inst_table[10000] = { 0 };
	ULONG64 g_SystemCallOrg[8] = { 0 };
	ULONG   g_SystemCall64Size = 0;
	void SystemCallbackPrint()
	{
		PMU_DEBUG_INFO_LN_EX("SystemCallbackPrint..... ");
	}

	ULONG64 GetCurrentCpuSystemCallOrg()
	{
		NT_ASSERT(g_SystemCallOrg[KeGetCurrentProcessorNumber()]);
		return g_SystemCallOrg[KeGetCurrentProcessorNumber()];
	}
	//--------------------------------------------------------------//
	// The PMI LVT handler routine (Warning! This should run at very high IRQL)
	VOID IntelPtPmiHandler(PKTRAP_FRAME pTrapFrame)
	{
		struct pebs_v1 *pebs, *end; // *pebs2, 
	//	PKDPC pProcDpc = NULL;									// This processor DPC
		MSR_IA32_PERF_GLOBAL_STATUS_DESC pmiDesc = { 0 };		// The PMI Interrupt descriptor
		MSR_IA32_PERF_GLOBAL_OVF_CTRL OvfCtrl = { 0 };
		LVT_Entry perfMonDesc = { 0 };							// The LVT Performance Monitoring register 
		PULONG lpdwApicBase = g_pDrvData.lpApicBase;			// The LVT Apic I/O space base address (if not in x2Apic mode)
		ULONG64 SystemCall64 = __readmsr(static_cast<ULONG>(Msr::Ia32Lstar));
	
		START_DO_WHILE

		if (g_IsUninit)
		{
			break;;
		}

 
		//	DWORD dwCurCpu = 0;

		if (g_printCount % 1000 == 0)
			PMU_DEBUG_INFO_LN_EX("[PROC Id: %d] IntelPtPmiHandler %p ", KeGetCurrentProcessorNumber(), pTrapFrame->Rip);

		MSR_IA32_PERF_GLOBAL_CTRL_VERSION2 Ctrl = { 0 };
		__writemsr(static_cast<ULONG>(Msr::Ia32PerfGlobalCtrl), Ctrl.all);

		OvfCtrl.fields.OvfBuf = true;
		__writemsr(static_cast<ULONG>(Msr::Ia32PerfGlobalOvfCtrl), OvfCtrl.all);

		__writemsr(static_cast<ULONG>(Msr::Ia32PMCx), (ULONG)0xFFFFFFFE);

		debug_store* ds_area = (debug_store*)__readmsr(static_cast<ULONG>(Msr::Ia32DsArea));
		end = (struct pebs_v1 *)ds_area->pebs_index;

		for (pebs = (struct pebs_v1 *)ds_area->pebs_base;// (struct pebs_v1 *)pebs2 = (struct pebs_v1 *)tmp->pebs_base;
			pebs < end;
			pebs = (struct pebs_v1 *)((char *)pebs + pebs_record_size))//, pebs2 = (struct pebs_v1 *)((char*) pebs2+ pebs_record_size))
		{
			u64 ip = pebs->ip;
			if (pebs_record_size >= sizeof(struct pebs_v2))
				ip = ((struct pebs_v2 *)pebs)->eventing_ip;
			 
			 

		} 
		if (pTrapFrame->Rip >= SystemCall64 && pTrapFrame->Rip <= SystemCall64 + 1400)
		{
			if (!GetHashIndexById(inst_table, 10000, pTrapFrame->Rip, NULL))
			{
				/*pTrapFrame->Rsp -= 8;
				*(PULONG64)pTrapFrame->Rsp = pTrapFrame->Rip;
				pTrapFrame->Rip = (ULONG64)AsmSysCallStub;*/
				PMU_DEBUG_INFO_LN_EX("[syscall/sysenter Cpu No. : %d] cr3: %p pTrapFrame->Rip: %p FaultAddr: %p sysycalladdr: %p ", 
					KeGetCurrentProcessorNumber(),	__readcr3(), pTrapFrame->Rip, pTrapFrame->FaultAddress , __readmsr(static_cast<ULONG>(Msr::Ia32Lstar)));
				SetHash(inst_table, 10000, pTrapFrame->Rip, NULL);
			}
			if (((pTrapFrame->Rip & 0xFFF )== 0xACE || 
				 (pTrapFrame->Rip & 0xFFF) == 0xA7A  ) && (g_printCount % 1000) == 0)
			{
				PMU_DEBUG_INFO_LN_EX("[Syscall exploting] Rip: %p rax: %x r10: %p ", pTrapFrame->Rip , pTrapFrame->Rax, pTrapFrame->R10);
			}
		} 

		/*	
			//Disable Hardware Breakpoint

			pTrapFrame->Dr0 = 0;
			pTrapFrame->Dr1 = 0; 
			pTrapFrame->Dr2 = 0; 
			pTrapFrame->Dr3 = 0;
		*/
		
		ds_area->pebs_index = ds_area->pebs_base;

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

		MSR_IA32_PEBS_ENABLE Pebs_Enable = { 0 };
		Pebs_Enable.fields.EnablePmc0 = true;
		__writemsr(static_cast<ULONG>(Msr::Ia32PebsEnable), Pebs_Enable.all);

		Ctrl.fields.EnablePmc0 = true;
		__writemsr(static_cast<ULONG>(Msr::Ia32PerfGlobalCtrl), Ctrl.all);

		END_DO_WHILE

		if (g_pDrvData.bCpuX2ApicMode)
		{
			// Check Intel Manuals, Vol. 3A section 10-37
			ULONGLONG perfMonEntry = __readmsr(MSR_IA32_X2APIC_LVT_PMI);
			perfMonDesc.All = (ULONG)perfMonEntry;
			perfMonDesc.Fields.Masked = 0;
			perfMonEntry = (ULONGLONG)perfMonDesc.All;
			__writemsr(MSR_IA32_X2APIC_LVT_PMI, perfMonEntry);
		}
		else {
			if (!lpdwApicBase)
				// XXX: Not sure how to continue, No MmMapIoSpace at this IRQL (should not happen)
				KeBugCheckEx(INTERRUPT_EXCEPTION_NOT_HANDLED, NULL, NULL, NULL, NULL);

			perfMonDesc.All = lpdwApicBase[0x340 / 4];
			perfMonDesc.Fields.Masked = 0;
			lpdwApicBase[0x340 / 4] = perfMonDesc.All;
		}

		g_printCount++;

		return;
	};

	// Register the LVT (Local Vector Table) PMI interrupt
	//--------------------------------------------------------------//
	NTSTATUS RegisterPmiInterrupt()
	{
		NTSTATUS ntStatus = STATUS_SUCCESS;						// Returned NTSTATUS
		PMIHANDLER pNewPmiHandler = NULL;
		//PMIHANDLER pOldPmiHandler = NULL; 					// The old PMI handler (currently not implemented)
		
		if (!g_SystemCall64Size)
		{
			//ULONG64 SystemCall64 = __readmsr(static_cast<ULONG>(Msr::Ia32Lstar));
		//	g_SystemCall64Size = SizeOfProc((void*)SystemCall64);
		}

		CHAR lpBuff[0x20] = { 0 };
		//XXX ULONG dwBytesIo = 0;								// Number of I/O bytes

		// First of all we need to search for HalpLocalApic symbol
		MSR_IA32_APIC_BASE_DESC ApicBase = { 0 };				// In Multi-processors systems this address could change
		ApicBase.All = __readmsr(MSR_IA32_APIC_BASE);			// In Windows systems all the processors LVT are mapped at the same physical address

		if (!ApicBase.Fields.EXTD) {
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
				return STATUS_NOT_SUPPORTED;

			// Now read the entry 0x340 (not really needed)
			//g_pDrvData->pmiVectDesc.All = lpdwApicBase[0x340 / 4];
		}
		else {
			// Current system uses x2APIC mode, no need to map anything
			g_pDrvData.bCpuX2ApicMode = TRUE;
		}


		// The following functions must be stored in HalDispatchTable 
		// TODO: Find a way to proper get the old PMI interrupt handler routine. Search inside the HAL code?
		// ntStatus = HalQuerySystemInformation(HalProfileSourceInformation, COUNTOF(lpBuff), (LPVOID)lpBuff, &dwBytesIo);		

		// Now set the new PMI handler, WARNING: we do not save and restore old handler
		pNewPmiHandler = IntelPtPmiHandler;
		ntStatus = HalSetSystemInformation(HalProfileSourceInterruptHandler, sizeof(PMIHANDLER), (PVOID)&pNewPmiHandler);
		if (NT_SUCCESS(ntStatus))
		{
			DbgPrintEx(0, 0, "[" DRV_NAME "] Successfully registered system PMI handler to function 0x%llX.\r\n", (PVOID)pNewPmiHandler);
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
			g_pDrvData.bPmiInstalled = FALSE;
			if (g_pDrvData.lpApicBase)
				MmUnmapIoSpace(g_pDrvData.lpApicBase, 0x1000);
		}

		return ntStatus;
	}

}