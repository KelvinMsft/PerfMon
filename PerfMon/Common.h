#pragma once
#include <intrin.h>
#include "x86.h"
#include "Apic.h"
#include "Util.h"
#define START_DO_WHILE do{
#define END_DO_WHILE   }while(FALSE); 

#define DRV_NAME	  "PerfMon"


typedef struct _PMU_INFORMATION
{
	UCHAR SupportedVersion;
	UCHAR SupportedFixedFunction;
	UCHAR SupportedBitWidth;
	UCHAR SupportedAnyThread;
	UCHAR SupportedNumOfPMCs;
	UCHAR SupporteWidthPerPMCs;
	UCHAR SupportedPerfEvents;
	UCHAR IsSupportPebs;
	UCHAR IsSupportEmon;
}PMUINFO, *PPMUINFO;


