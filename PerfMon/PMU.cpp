#include <ntddk.h>
#include "PMU.h"
#include "Common.h"

//--------------------------------------------------------------//
NTSTATUS PMUEnvironmentCheck(
	_Out_ PMUINFO* Info
)
{
	UCHAR version = 0;
	UCHAR SupportedFixedFunction = 0;
	UCHAR SupportedBitWidth = 0;
	UCHAR SupportedPerfEvents = 0;
	UCHAR SupportedNumOfPMCs = 0;
	UCHAR SupportedPMCsWidth = 0;
	int cpu_info[4];
	NTSTATUS status = STATUS_SUCCESS;

	START_DO_WHILE   
	if (!Info)
	{
		DbgPrintEx(0, 0, "Computer is not supported PMU Version : %d \r\n", cpu_info[0]);
		status = STATUS_UNSUCCESSFUL;
		break;
	}
	
	__cpuid(cpu_info, 0xA);
	version = (UCHAR)(cpu_info[0] & 0xFF);
	SupportedNumOfPMCs = (UCHAR)((cpu_info[0] >> 8) & 0xFF);
	SupportedPMCsWidth = (UCHAR)((cpu_info[0] >> 16) & 0xFF);
	SupportedPerfEvents = (UCHAR)((cpu_info[1] & 0xFF));
	SupportedFixedFunction = (UCHAR)(cpu_info[3] & 0x1F);
	SupportedBitWidth = (UCHAR)((cpu_info[3] >> 5) & 0xFF);

	if (!version)
	{
		DbgPrintEx(0, 0, "Computer is not supported PMU Version : %d \r\n", cpu_info[0]);
		status = STATUS_UNSUCCESSFUL;
		break;
	}
	 
	Info->SupportedVersion = version;
	Info->SupportedFixedFunction = SupportedFixedFunction;
	Info->SupportedBitWidth = SupportedBitWidth;
	Info->SupportedNumOfPMCs = SupportedNumOfPMCs;
	Info->SupporteWidthPerPMCs = SupportedPMCsWidth;
	Info->SupportedAnyThread = (version == 3) ? 1 : 0; 
	Info->SupportedPerfEvents = SupportedPerfEvents;
	END_DO_WHILE

	return status;
}
 

//--------------------------------------------------------------//
NTSTATUS PMUInitiailization(
	_In_ PVOID info
)
{
	PMUINFO* Info = (PMUINFO*)info;
	if (!Info)
	{
		return STATUS_UNSUCCESSFUL;
	}

	switch (Info->SupportedVersion)
	{
	case 0:
		break;
	case 1:
		break;
	case 2:
		break;
	case 3: 
		MSR_IA32_PERF_GLOBAL_CTRL_VERSION2 Ctrl = { 0 };
		Ctrl.fields.EnableCTR0 = true;
		Ctrl.fields.EnableCTR1 = true;
		Ctrl.fields.EnableCTR2 = true;
		Ctrl.fields.EnablePmc0 = true;
		Ctrl.fields.EnablePmc1 = true; 
		__writemsr(static_cast<ULONG>(Msr::Ia32PerfGlobalCtrl), Ctrl.all);

		MSR_IA32_PERFEVTSELX_VERSION3 PerfEvtSelx = { 0 };
		PerfEvtSelx.fields.Usr = true;
		PerfEvtSelx.fields.Os = true;
		PerfEvtSelx.fields.E = false;
		PerfEvtSelx.fields.Int = true;
		PerfEvtSelx.fields.CounterMask = 0;
		PerfEvtSelx.fields.En = true;
		PerfEvtSelx.fields.AnyThread = true;
		PerfEvtSelx.fields.EventSelect = 0xC0;
		PerfEvtSelx.fields.UnitMask = 0;
		PerfEvtSelx.fields.Inv = false; 
		PerfEvtSelx.fields.Pc = false;
		int i = 0;
		while (i < 10) {
			__writemsr(static_cast<ULONG>(Msr::Ia32PMCx), 0xffffffff);
			__writemsr(static_cast<ULONG>(Msr::Ia32PerfEvtseLx), PerfEvtSelx.all);

			DbgPrintEx(0, 0, "[PROC ID: %d] Write Msr %x Now: %I64x pmc: %I64x \r\n",
				KeGetCurrentProcessorNumber(), PerfEvtSelx.all, __readmsr(static_cast<ULONG>(Msr::Ia32PerfEvtseLx)), __readmsr(static_cast<ULONG>(Msr::Ia32PMCx)));
			i++;
		}
		break;
	}
	return STATUS_SUCCESS;
}

//--------------------------------------------------------------//
NTSTATUS PMUUnInitiailization(
	_In_ PVOID info
)
{
	PMUINFO* Info = (PMUINFO*)info;
	if (!Info)
	{
		return STATUS_UNSUCCESSFUL;
	}

	switch (Info->SupportedVersion)
	{
	case 0:
		break;
	case 1:
		break;
	case 2:
		break;
	case 3:
		break;
	}
	return STATUS_SUCCESS;
}
