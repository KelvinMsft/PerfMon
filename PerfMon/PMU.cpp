#include <ntddk.h>
#include "PMU.h"
#include "Common.h"
#include "Log.h"
#include <intrin.h>
#include "PMI.h"
extern "C"
{  
	////////////////////////////////////////////////////////////////////
	//// Types
	////  


	////////////////////////////////////////////////////////////////////
	////  Marcos
	////  
	#define PEBS_BUFFER_SIZE	(64 * 1024) /* PEBS buffer size */
	#define OUT_BUFFER_SIZE		(64 * 1024) /* must be multiple of 4k */
 
	////////////////////////////////////////////////////////////////////
	////  Global Variable
	////  
	UCHAR g_Event = 0;
	UCHAR g_Mask = 0;
	ULONG pebs_record_size = 0;

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
		Info->IsSupportEmon = (MiscEnable.fields.PerfMonAvaliable);

		END_DO_WHILE

		return status;
	}
	//------------------------------------------------------//
	NTSTATUS CheckMircoArchitecture(
		_In_ ULONG Model)
	{ 
		switch (Model)
		{
		case 58: /* IvyBridge */
		case 60:
		case 63: /* Haswell_EP */
		case 69: /* Haswell_ULT */
		case 94: /* Skylake */
			g_Event = 0xc4; /* UOPS_RETIRED.ALL */
			g_Mask = 0x40;
			break;

		case 55: /* Bay Trail */
		case 76: /* Airmont */
		case 77: /* Avoton */
			g_Event = 0x0c5; /* BR_MISP_RETIRED.ALL_BRANCHES */
			break;

		default:
			PMU_DEBUG_INFO_LN_EX("Unknown CPU model %d\n", Model);
			return STATUS_UNSUCCESSFUL;
		}
		return STATUS_SUCCESS;
	}
	//------------------------------------------------------//
	NTSTATUS CheckPerfCap(
		_In_ ULONG feat1)
	{
		/* check perf capability */
		if (feat1 & (1 << 15))
		{
			ULONG64 cap;

			cap = __readmsr(static_cast<ULONG>(Msr::Ia32PerfCaps));
			switch ((cap >> 8) & 0xf) {
			case 1:
				pebs_record_size = sizeof(struct pebs_v1);
				break;
			case 2:
				pebs_record_size = sizeof(struct pebs_v2);
				break;
			case 3:
				pebs_record_size = sizeof(struct pebs_v3);
				break;
			default:
			{
				PMU_DEBUG_INFO_LN_EX("Unsupported PEBS format\n");
				return STATUS_UNSUCCESSFUL;
			}
			}
			/* Could check PEBS_TRAP */
		}
		else
		{
			PMU_DEBUG_INFO_LN_EX("No PERF_CAPABILITIES support\n"); 
			return STATUS_UNSUCCESSFUL;
		}

		return STATUS_SUCCESS;
	}
	//------------------------------------------------------//
	NTSTATUS CheckSupportDebugStore(
		_In_ ULONG Feat2)
	{
		/* check if we support DS */
		if (!(Feat2 & (1 << 21)))
		{
			PMU_DEBUG_INFO_LN_EX("No debug store support\n");
			return STATUS_UNSUCCESSFUL;
		}
		return STATUS_SUCCESS;
	}
	//------------------------------------------------------//
	NTSTATUS CheckArchPlatform(
		_In_ ULONG Max)
	{
		NTSTATUS status = STATUS_SUCCESS;
		START_DO_WHILE
		int cpu_info[4] = { 0 };
		if (Max >= 0xa) 
		{
			__cpuid(cpu_info, 0xA);
			if ((cpu_info[0] & 0xff) < 1)
			{
				PMU_DEBUG_INFO_LN_EX("No arch perfmon support\n");
				status = STATUS_UNSUCCESSFUL;
				break;
			}

			if (((cpu_info[0] >> 8) & 0xff) < 1)
			{
				PMU_DEBUG_INFO_LN_EX("No generic counters\n"); 
				status = STATUS_UNSUCCESSFUL;
				break;
			}
		}
		else
		{
			PMU_DEBUG_INFO_LN_EX("No arch perfmon support\n");

			status = STATUS_UNSUCCESSFUL;
			break;
		}

		END_DO_WHILE

		return status;
	} 
	//------------------------------------------------------//
	NTSTATUS GetFamilyAndModel(
		_In_ int* CpuInfo , 
		_In_ int* Model,
		_In_ int* Family
	)
	{
		NTSTATUS status = STATUS_SUCCESS;
		START_DO_WHILE
		if (!CpuInfo ||!Model || !Family)
		{
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		 
		*Model = ((CpuInfo[0] >> 4) & 0xf);
		*Family = (CpuInfo[0] >> 8) & 0xf;
		if (*Family == 6 || *Family == 0xf)
		{
			*Model += ((CpuInfo[0] >> 16) & 0xf) << 4;
		}

		END_DO_WHILE  
		return status;
	}

	//------------------------------------------------------//
	NTSTATUS CheckCpu()
	{
		int cpu_info[4] = {0};
		int max, model, fam;
		unsigned feat1, feat2;
		NTSTATUS status = STATUS_SUCCESS;;
		START_DO_WHILE

		__cpuid(cpu_info, 0);
		if (memcmp(&cpu_info[1], "Genu", 4)) 
		{
			PMU_DEBUG_INFO_LN_EX("Not an Intel CPU\n");
			break;
		} 
		max = cpu_info[0];

		__cpuid(cpu_info, 1); 
		feat1 = cpu_info[2];
		feat2 = cpu_info[3]; 

		status = GetFamilyAndModel(cpu_info, &model, &fam);
		if (!NT_SUCCESS(status) || fam != 6)
		{
			PMU_DEBUG_INFO_LN_EX("Not an supported Intel CPU\n");
			break;
		}

		status = CheckMircoArchitecture(model);
		if (!NT_SUCCESS(status))
		{
			break;
		}

		status = CheckArchPlatform(max);
		if (!NT_SUCCESS(status))
		{
			break;
		}

		status = CheckSupportDebugStore(feat2);
		if (!NT_SUCCESS(status))
		{
			break;
		}

		status = CheckPerfCap(feat1);
		if (!NT_SUCCESS(status))
		{
			break;
		}

		PMU_DEBUG_INFO_LN_EX("Supported CPU : %x %x pebs_record_size: %x ", g_Mask, g_Event, pebs_record_size);

		END_DO_WHILE 
 
		return status;
	} 

	//--------------------------------------------------------------//
	VOID DisablePmi()
	{
		MSR_IA32_PERF_GLOBAL_CTRL_VERSION2 Ctrl = { 0 };
		__writemsr(static_cast<ULONG>(Msr::Ia32PerfGlobalCtrl), Ctrl.all);
	}
	//--------------------------------------------------------------//
	VOID EnablePmi()
	{
		MSR_IA32_PERF_GLOBAL_CTRL_VERSION2 Ctrl = { 0 };
		Ctrl.fields.EnablePmc0 = true;
		__writemsr(static_cast<ULONG>(Msr::Ia32PerfGlobalCtrl), Ctrl.all);
	}

	//--------------------------------------------------------------//
	NTSTATUS PMUInitiailization(
		_In_ PVOID info
	)
	{
		START_DO_WHILE

			PMUINFO* Info = (PMUINFO*)info;
		if (!Info || !NT_SUCCESS(CheckCpu()))
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
	
			DisablePmi();

			__writemsr(static_cast<ULONG>(Msr::Ia32PMCx), (ULONG)0xFFFFFFFE);

			MSR_IA32_PERFEVTSELX_VERSION3 PerfEvtSelx = { 0 };
			PerfEvtSelx.fields.Usr = true;						//in case you want intercept user mode instruction...
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
		
			PMU_DEBUG_INFO_LN_EX("Id: %x %d Done....", __readmsr(static_cast<ULONG>(Msr::Ia32PerfEvtseLx)), KeGetCurrentProcessorNumber());

			break;
		}

		END_DO_WHILE
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
}