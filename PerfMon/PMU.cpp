#include <ntddk.h>
#include "PMU.h"
#include "Common.h"
#include "Log.h"
#include <intrin.h>
#define PERIOD 100003


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
	 
	MSR_IA32_MISC_ENABLE MiscEnable = { __readmsr(static_cast<ULONG>(Msr::Ia32MiscEnable)) };
	
	Info->SupportedVersion = version;
	Info->SupportedFixedFunction = SupportedFixedFunction;
	Info->SupportedBitWidth = SupportedBitWidth;
	Info->SupportedNumOfPMCs = SupportedNumOfPMCs;
	Info->SupporteWidthPerPMCs = SupportedPMCsWidth;
	Info->SupportedAnyThread = (version == 3) ? 1 : 0; 
	Info->SupportedPerfEvents = SupportedPerfEvents;
	Info->IsSupportPebs = (!MiscEnable.fields.PEBSUnavaiable);

	END_DO_WHILE

	return status;
}
UCHAR g_Event = 0;
UCHAR g_Mask = 0;
ULONG pebs_record_size = 0;
//------------------------------------------------------//
static bool check_cpu(void)
{
	int cpu_info[4];
	int max, model, fam;
	unsigned feat1, feat2;

	__cpuid(cpu_info, 0);
	if (memcmp(&cpu_info[1], "Genu", 4)) {
		PMU_DEBUG_INFO_LN_EX("Not an Intel CPU\n");
		return false;
	}

	max = cpu_info[0];

	__cpuid(cpu_info, 1);

	feat1 = cpu_info[2];
	feat2 = cpu_info[3];

	model = ((cpu_info[0] >> 4) & 0xf);
	fam = (cpu_info[0] >> 8) & 0xf;
	if (fam == 6 || fam == 0xf)
		model += ((cpu_info[0] >> 16) & 0xf) << 4;
	if (fam != 6) {
		PMU_DEBUG_INFO_LN_EX("Not an supported Intel CPU\n");
		return false;
	}

	switch (model) {
	case 58: /* IvyBridge */
	case 63: /* Haswell_EP */
	case 69: /* Haswell_ULT */
	case 94: /* Skylake */
		g_Event = 0xc2; /* UOPS_RETIRED.ALL */
		g_Mask = 0x1;
		break;

	case 55: /* Bay Trail */
	case 76: /* Airmont */
	case 77: /* Avoton */
		g_Event = 0x0c5; /* BR_MISP_RETIRED.ALL_BRANCHES */
		break;

	default:
		PMU_DEBUG_INFO_LN_EX("Unknown CPU model %d\n", model);
		return false;
	}

	/* Check if we support arch perfmon */
	if (max >= 0xa) {
		__cpuid(cpu_info, 0xA);
		if ((cpu_info[0] & 0xff) < 1) {
			PMU_DEBUG_INFO_LN_EX("No arch perfmon support\n");
			return false;
		}
		if (((cpu_info[0] >> 8) & 0xff) < 1) {
			PMU_DEBUG_INFO_LN_EX("No generic counters\n");
			return false;
		}
	}
	else {
		PMU_DEBUG_INFO_LN_EX("No arch perfmon support\n");
		return false;
	}

	/* check if we support DS */
	if (!(feat2 & (1 << 21))) {
		PMU_DEBUG_INFO_LN_EX("No debug store support\n");
		return false;
	}
	
	/* check perf capability */

	if (feat1 & (1 << 15)) {
		ULONG64 cap;

		cap = __readmsr(static_cast<ULONG>(Msr::Ia32PerfCaps));
		switch ((cap >> 8) & 0xf) {
		case 1:
			pebs_record_size = 1; //sizeof(struct pebs_v1);
			break;
		case 2:
			pebs_record_size = 2;// sizeof(struct pebs_v2);
			break;
		case 3:
			pebs_record_size = 3;// sizeof(struct pebs_v3);
			break;
		default:
			PMU_DEBUG_INFO_LN_EX("Unsupported PEBS format\n");
			return false;
		}
		/* Could check PEBS_TRAP */
	}
	else {
		PMU_DEBUG_INFO_LN_EX("No PERF_CAPABILITIES support\n");
		return false;
	}
	
	PMU_DEBUG_INFO_LN_EX("Supported CPU : %x %x pebs_record_size: %x ", g_Mask, g_Event, pebs_record_size);


	return true;
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
	/*	Ctrl.fields.EnableCTR0 = true;
		Ctrl.fields.EnableCTR1 = true;
		Ctrl.fields.EnableCTR2 = true;
		Ctrl.fields.EnablePmc0 = true;
		Ctrl.fields.EnablePmc1 = true; 
		*/

		if (check_cpu())
		{
			MSR_IA32_PERF_GLOBAL_CTRL_VERSION2 Ctrl = { 0 };
			__writemsr(static_cast<ULONG>(Msr::Ia32PerfGlobalCtrl), Ctrl.all);

			__writemsr(static_cast<ULONG>(Msr::Ia32PMCx), (ULONG64)-PERIOD);

			MSR_IA32_PERFEVTSELX_VERSION3 PerfEvtSelx = { 0 };
			PerfEvtSelx.fields.Usr = true;
			PerfEvtSelx.fields.Os = true;
			PerfEvtSelx.fields.E = false;
			PerfEvtSelx.fields.Int = true;
			PerfEvtSelx.fields.CounterMask = 0;
			PerfEvtSelx.fields.En = true;
			PerfEvtSelx.fields.AnyThread = false;
			PerfEvtSelx.fields.EventSelect = g_Event;
			PerfEvtSelx.fields.UnitMask = g_Mask;
			PerfEvtSelx.fields.Inv = false;
			PerfEvtSelx.fields.Pc = false;
			__writemsr(static_cast<ULONG>(Msr::Ia32PerfEvtseLx), PerfEvtSelx.all);

		/*	MSR_IA32_PEBS_ENABLE Pebs_Enable = { 0 };
			Pebs_Enable.fields.EnablePmc0 = true;
			__writemsr(static_cast<ULONG>(Msr::Ia32PebsEnable), Pebs_Enable.all);

			Ctrl.fields.EnablePmc0 = true;
			__writemsr(static_cast<ULONG>(Msr::Ia32PerfGlobalCtrl), Ctrl.all);
	*/
			PMU_DEBUG_INFO_LN_EX("Id: %d Done....", KeGetCurrentProcessorNumber());

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
