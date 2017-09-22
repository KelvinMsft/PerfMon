#include <ntddk.h>
#include "PMI.h"
#include "Apic.h"
#include "Common.h"

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

//--------------------------------------------------------------//
// The PMI LVT handler routine (Warning! This should run at very high IRQL)
VOID IntelPtPmiHandler(PKTRAP_FRAME pTrapFrame)
{
	//	PKDPC pProcDpc = NULL;									// This processor DPC
	MSR_IA32_PERF_GLOBAL_STATUS_DESC pmiDesc = { 0 };		// The PMI Interrupt descriptor
	LVT_Entry perfMonDesc = { 0 };							// The LVT Performance Monitoring register
	PULONG lpdwApicBase = g_pDrvData.lpApicBase;			// The LVT Apic I/O space base address (if not in x2Apic mode)
	DWORD dwCurCpu = 0;
	DbgPrintEx(0, 0, "[PROC Id: %d] IntelPtPmiHandler", KeGetCurrentProcessorNumber());
	//PER_PROCESSOR_PT_DATA * pCurCpuData = NULL;				// The Per-Processor data structure
	//PT_BUFFER_DESCRIPTOR * ptBuffDesc = NULL;				// The PT Buffer descriptor
	UNREFERENCED_PARAMETER(pTrapFrame);

	ASSERT(KeGetCurrentIrql() > DISPATCH_LEVEL);

	dwCurCpu = KeGetCurrentProcessorNumber();

	// Check if the interrupt is mine
	pmiDesc.All = __readmsr(MSR_IA32_PERF_GLOBAL_STATUS);
	if (pmiDesc.Fields.TraceToPAPMI == 0)
		return;

	/*
	// Check the Intel PT status
	MSR_RTIT_STATUS_DESC traceStatusDesc = { 0 };
	traceStatusDesc.All = __readmsr(MSR_IA32_RTIT_STATUS);
	if (traceStatusDesc.Fields.Error)
	DrvDbgPrint("[" DRV_NAME "] Warning: Intel PT Pmi has raised, but the PT Status register indicates an error!\r\n");

	if (ptBuffDesc && ptBuffDesc->bDefaultPmiSet) {
	// Queue a DPC only if the Default PMI handler is set
	ptBuffDesc->bBuffIsFull = TRUE;

	// The IRQL is too high so we use DPC
	pProcDpc = (PKDPC)ExAllocatePoolWithTag(NonPagedPool, sizeof(KDPC), MEMTAG);
	KeInitializeDpc(pProcDpc, IntelPmiDpc, NULL);
	KeSetTargetProcessorDpc(pProcDpc, (CCHAR)dwCurCpu);
	KeInsertQueueDpc(pProcDpc, (LPVOID)dwCurCpu, NULL);
	}

	MSR_IA32_PERF_GLOBAL_OVF_CTRL_DESC globalResetMsrDesc = { 0 };
	// Set the PMI Reset: Once the ToPA PMI handler has serviced the relevant buffer, writing 1 to bit 55 of the MSR at 390H
	// (IA32_GLOBAL_STATUS_RESET)clears IA32_PERF_GLOBAL_STATUS.TraceToPAPMI.
	globalResetMsrDesc.Fields.ClrTraceToPA_PMI = 1;
	__writemsr(MSR_IA32_PERF_GLOBAL_OVF_CTRL, globalResetMsrDesc.All);

	// Call the External PMI handler (if any)
	if (g_pDrvData->pCustomPmiIsr) {
	g_pDrvData->pCustomPmiIsr(dwCurCpu, ptBuffDesc);
	}
	*/

	// Re-enable the PMI
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
 
	DbgPrintEx(0, 0, "KTRAP_FRAME: %p", pTrapFrame);
	return;
};
 
// Register the LVT (Local Vector Table) PMI interrupt
//--------------------------------------------------------------//
NTSTATUS RegisterPmiInterrupt()
{
	NTSTATUS ntStatus = STATUS_SUCCESS;						// Returned NTSTATUS
	PMIHANDLER pNewPmiHandler = NULL;
	//PMIHANDLER pOldPmiHandler = NULL; 					// The old PMI handler (currently not implemented)

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
