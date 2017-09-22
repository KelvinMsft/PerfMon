#pragma once


#include <ntddk.h>

typedef ULONG DWORD;

// The APIC Base physical address MSR in xAPIC Mode
union MSR_IA32_APIC_BASE_DESC {
	struct {
		ULONGLONG Reserved1 : 8;			// [0:7] - Reserved
		ULONGLONG Bsp : 1;					// [8] - Indicates if the processor is the bootstrap processor (BSP)
		ULONGLONG Reserved2 : 1;			// [9] - Reserved
		ULONGLONG EXTD : 1;					// [10] - Enable x2APIC mode
		ULONGLONG EN : 1;					// [11] - APIC global enable/disable
		ULONGLONG ApicBase : 24;			// [12:35] - Base Physical Address
	} Fields;
	ULONGLONG All;
}; 


// A local vector table (LVT) entry
union LVT_Entry {
	struct {
		USHORT Vector : 8;					// [0:7] - The Vector number
		USHORT Reserved1 : 4;				// [8:11] - Reserved
		USHORT DeliveryStatus : 1;			// [12] - Delivery status: 0 - Idle; 1 - Send Pending;
		USHORT Reserved2 : 3;				// [13:15] - Reserved
		USHORT Masked : 1;					// [16] - Masked: 0 - Not Masked; 1 - Masked
		USHORT TimerMode : 2;				// [17:18] - Timer mode: 00 - One-shot; 01 - Periodic; 10 - TSC-Deadline;
		USHORT Reserved3 : 13;				// [19:31] - Reserved
	} Fields;
	DWORD All;
};

// The IA32_PERF_GLOBAL_STATUS descriptor of Intel Broadwell microarchitecture 
union MSR_IA32_PERF_GLOBAL_STATUS_DESC {
	struct {
		DWORD PMC0_OVF : 1;					// [0] - Read only
		DWORD PMC1_OVF : 1;					// [1] - Read only 
		DWORD PMC2_OVF : 1;					// [2] - Read only
		DWORD PMC3_OVF : 1;					// [3] - Read only
		DWORD PMC4_OVF : 1;					// [4] - Read only (if PMC4 present)
		DWORD PMC5_OVF : 1;					// [5] - Read only (if PMC5 present) 
		DWORD PMC6_OVF : 1;					// [6] - Read only (if PMC6 present)
		DWORD PMC7_OVF : 1;					// [7] - Read only (if PMC7 present)
		DWORD Reserved : 24;				// [8:31] - Reserved
		DWORD FIXED_CTR0 : 1;				// [32] - FIXED_CTR0 Overflow (RO)
		DWORD FIXED_CTR1 : 1;				// [33] - FIXED_CTR1 Overflow (RO)
		DWORD FIXED_CTR2 : 1;				// [34] - FIXED_CTR2 Overflow (RO)
		DWORD Reserved2 : 20;				// [35:54] - Reserved
		DWORD TraceToPAPMI : 1;				// [55] - The ToPA PMI Interrupt status
		DWORD Reserved3 : 5;				// [56:60] - Reserved
		DWORD Ovf_UncorePMU : 1;			// [61]
		DWORD Ovf_Buffer : 1;				// [62]
		DWORD CondChgd : 1;					// [63]
	} Fields;
	ULONGLONG All;
};
