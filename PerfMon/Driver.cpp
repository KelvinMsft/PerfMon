  
#include <ntddk.h> 
#include "Apic.h"
#include "x86.h"
#include "PMU.h"
#include "Common.h"
#include "PMI.h"
extern "C"
{
 
	 

	//////////////////////////////////////////////////////////////////
	////	Prototype	
	////	
	////
 

	//////////////////////////////////////////////////////////////////
	////	Global Variable	
	////	
	////
 
	PMUINFO			   g_EnvironmentInfo;

	//////////////////////////////////////////////////////////////////
	////	Marco
	////	
	////
 
	 
 
	//--------------------------------------------------------------//
	VOID DrvUnload(
			_In_ struct _DRIVER_OBJECT *DriverObject)
	{
		UNREFERENCED_PARAMETER(DriverObject);
		UnregisterPmiInterrupt();
		return;
	} 
	 
	// Sleep the current thread's execution for Millisecond milli-seconds.
	_Use_decl_annotations_ NTSTATUS UtilSleep(LONG Millisecond) {
		PAGED_CODE();

		LARGE_INTEGER interval = {};
		interval.QuadPart = -(10000 * Millisecond);  // msec
		return KeDelayExecutionThread(KernelMode, FALSE, &interval);
	}
	//--------------------------------------------------------------//
	NTSTATUS DriverEntry(
		_In_	PDRIVER_OBJECT DrvObj,
		_In_	PCUNICODE_STRING RegistryString)
	{ 
		UNREFERENCED_PARAMETER(RegistryString);
		NTSTATUS status = STATUS_SUCCESS;
		START_DO_WHILE
	 
		status = RegisterPmiInterrupt();
		if (!NT_SUCCESS(status))
		{ 
			break;
		}
 
		status = PMUEnvironmentCheck(&g_EnvironmentInfo);
		if (!NT_SUCCESS(status))
		{ 
			break;
		}
		 
		status = UtilForEachProcessor(PMUInitiailization, &g_EnvironmentInfo);
		if (!NT_SUCCESS(status))
		{ 
			break;
		}

		DbgPrintEx(0, 0, "Computer is supported PMU SupportedVersion : %d SupportedFixedFunction: %d  SupportedBitWidth:  %d\
						  SupportedAnyThread: %d SupportedNumOfPMCs: %d  SupporteWidthPerPMCs: %d  SupportedPerfEvents: %d \r\n",
			g_EnvironmentInfo.SupportedVersion,
			g_EnvironmentInfo.SupportedFixedFunction,
			g_EnvironmentInfo.SupportedBitWidth,
			g_EnvironmentInfo.SupportedAnyThread,
			g_EnvironmentInfo.SupportedNumOfPMCs,
			g_EnvironmentInfo.SupporteWidthPerPMCs,
			g_EnvironmentInfo.SupportedPerfEvents
		); 
		 
		DrvObj->DriverUnload = DrvUnload;

		END_DO_WHILE

		return status;
	}
	//--------------------------------------------------------------//
}