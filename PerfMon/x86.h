#pragma once

#define MSR_IA32_PERF_GLOBAL_STATUS		0x0000038E
#define MSR_IA32_APIC_BASE				0x0000001B			// The APIC base address register
#define MSR_IA32_PERF_GLOBAL_OVF_CTRL	0x00000390			// Aka IA32_GLOBAL_STATUS_RESET
#define MSR_IA32_RTIT_OUTPUT_BASE		0x00000560
#define MSR_IA32_RTIT_OUTPUT_MASK_PTRS	0x00000561
#define MSR_IA32_RTIT_CTL				0x00000570
#define MSR_IA32_RTIT_STATUS			0x00000571
#define MSR_IA32_X2APIC_LVT_PMI			0x00000834

// Filtering by CR3:
#define MSR_IA32_RTIT_CR3_MATCH			0x00000572

// Filtering by IP:
#define MSR_IA32_RTIT_ADDR0_START		0x00000580
#define MSR_IA32_RTIT_ADDR0_END			0x00000581
#define MSR_IA32_RTIT_ADDR1_START		0x00000582
#define MSR_IA32_RTIT_ADDR1_END			0x00000583
#define MSR_IA32_RTIT_ADDR2_START		0x00000584
#define MSR_IA32_RTIT_ADDR2_END			0x00000585
#define MSR_IA32_RTIT_ADDR3_START		0x00000586
#define MSR_IA32_RTIT_ADDR3_END			0x00000587

/*------------------------------------------------------------------
18.2.1.2 Pre-defined Architectural Performance Events : 
----------------------------------------------------------------
| Bit Position | Event Name              | UMask | Event Select |
| (CPUID.AH.EBX)										        |
 ---------------------------------------------------------------
|  0			UnHalted Core Cycles       00H		 3CH		|
|  1			Instruction Retired        00H		 C0H		|
|  2			UnHalted Reference Cycles  01H		 3CH		|
|  3			LLC Reference			   4FH		 2EH		|
|  4			LLC Misses				   41H		 2EH		|
|  5			Branch Instruction Retired 00H		 C4H		|
|  6			Branch Misses Retired	   00H		 C5H		|
-----------------------------------------------------------------

------------------------------------------------------------------*/
union MSR_IA32_PERFEVTSLX_VERSION1
{
	struct
	{
		ULONG64 EventSelect : 8;	///< [7:0]	 Event Select Field
		ULONG64 UnitMask : 8;		///< [15:8]	 Unit Mask
		ULONG64 Usr : 1;			///< [16]	 User Mode
		ULONG64 Os : 1;				///< [17]	 Operating System Mode
		ULONG64 E : 1;				///< [18]	 Edge Detect
		ULONG64 Pc : 1;				///< [19]	 Pin Control
		ULONG64 Int : 1;			///< [20]	 APIC Interrupt Enable
		ULONG64 Reserved : 1;		///< [21]	 Resevred
		ULONG64 En : 1;				///< [22]	 Enable Counters
		ULONG64 Inv : 1;			///< [23]    Invert
		ULONG64 CounterMask : 8;	///< [31:24] Counter Mask
		ULONG64 Reserved2 : 32;		///< [63:32] Reserved
	}fields;
	ULONG64 all;
}; 
static_assert(sizeof(MSR_IA32_PERFEVTSLX_VERSION1) == 8, "Size check");

union MSR_IA32_PERFEVTSELX_VERSION3
{
	struct
	{
		ULONG64 EventSelect : 8;	///< [7:0]	 Event Select Field
		ULONG64 UnitMask : 8;		///< [15:8]	 Unit Mask
		ULONG64 Usr : 1;			///< [16]	 User Mode
		ULONG64 Os : 1;				///< [17]	 Operating System Mode
		ULONG64 E : 1;				///< [18]	 Edge Detect
		ULONG64 Pc : 1;				///< [19]	 Pin Control
		ULONG64 Int : 1;			///< [20]	 APIC Interrupt Enable
		ULONG64 AnyThread : 1;		///< [21]	 AnyThread
		ULONG64 En : 1;				///< [22]	 Enable Counters
		ULONG64 Inv : 1;			///< [23]    Invert
		ULONG64 CounterMask : 8;	///< [31:24] Counter Mask
		ULONG64 Reserved2 : 32;		///< [63:32] Reserved
	}fields;
	ULONG64 all;
}; 
static_assert(sizeof(MSR_IA32_PERFEVTSELX_VERSION3) == 8, "Size check");


//bit[0]:  0: disable; 1: OS; 2: User; 3: All ring levels 
//bit[1]   Controls for IA32_FIXED_CTRx , x < 3 , Enable for fixed-function PC to increment
union MSR_IA32_FIXED_CTR_CTRL_VERSION2
{
	struct
	{
		ULONG64 En : 2;			 /// < [1:0]	Enable Field,	 
		ULONG64 Reserved1 : 1;   /// < [2]		Reserved1	
		ULONG64 Pmi : 1;		 /// < [3]		PMI Field	,	Enable PMI Overflow	
		ULONG64 En2 : 2;		 /// < [5:4]	Enable Field2
		ULONG64 Reserved2 : 1;	 /// < [6]		Reserved2
		ULONG64 Pmi2 : 1;		 /// < [7]		PMI Field
		ULONG64 En3 : 2;		 /// < [9:8]	Enable Field2
		ULONG64 Reserved4 : 1;	 /// < [10]		Reserved2
		ULONG64 Pmi3 : 1;		 /// < [11]		PMI Field	
		ULONG64 Reserved5 : 52;  /// < [63:12]  Reserved	
	}fields;
	ULONG64 all;
};
static_assert(sizeof(MSR_IA32_FIXED_CTR_CTRL_VERSION2) == 8, "Size check");
 

//bit[0]:  0: disable; 1: OS; 2: User; 3: All ring levels 
//bit[1]   Controls for IA32_FIXED_CTRx , x < 3 , Enable for fixed-function PC to increment
union MSR_IA32_FIXED_CTR_CTRL_VERSION3
{
	struct
	{
		ULONG64 En : 2;			 /// < [1:0]	Enable Field,	 
		ULONG64 Any1 : 1;		 /// < [2]		Reserved1	
		ULONG64 Pmi : 1;		 /// < [3]		PMI Field	,	Enable PMI Overflow	
		ULONG64 En2 : 2;		 /// < [5:4]	Enable Field2
		ULONG64 Any12 : 1;		 /// < [6]		Reserved2
		ULONG64 Pmi2 : 1;		 /// < [7]		PMI Field
		ULONG64 En3 : 2;		 /// < [9:8]	Enable Field2
		ULONG64 Any13 : 1;		 /// < [10]		Reserved2
		ULONG64 Pmi3 : 1;		 /// < [11]		PMI Field	
		ULONG64 Reserved5 : 52;  /// < [63:12]  Reserved	
	}fields;
	ULONG64 all;
};
static_assert(sizeof(MSR_IA32_FIXED_CTR_CTRL_VERSION3) == 8, "Size check");

union MSR_IA32_PERF_GLOBAL_CTRL_VERSION2
{
	struct
	{
		ULONG64 EnablePmc0 : 1;			 /// < [0]	IA32_PMC0 Enabled
		ULONG64 EnablePmc1 : 1;			 /// < [1]	IA32_PMC0 Enabled
		ULONG64 Reserved   : 30;		 /// < [31:2]
		ULONG64	EnableCTR0 : 1;			 /// < [32] IA32_FIXED_CTR0 enable
		ULONG64	EnableCTR1 : 1;			 /// < [33] IA32_FIXED_CTR1 enable
		ULONG64	EnableCTR2 : 1;			 /// < [34] IA32_FIXED_CTR2 enable
		ULONG64	Reserved2  : 29;		 /// < [63:35]
	}fields;
	ULONG64 all;
};
static_assert(sizeof(MSR_IA32_PERF_GLOBAL_CTRL_VERSION2) == 8, "Size check");


union MSR_IA32_PERF_GLOBAL_STATUS_VERSION2
{
	struct
	{
		ULONG64 PMC0Overflow : 1;	 /// < [0]	IA32_PMC0 OverFlow
		ULONG64 PMC1Overflow : 1;	 /// < [1]	IA32_PMC0 OverFlow
		ULONG64 Reserved : 30;		 /// < [31:2]
		ULONG64	CTR0OverFlow : 1;	 /// < [32] IA32_FIXED_CTR0 OverFlow
		ULONG64	CTR1OverFlow : 1;	 /// < [33] IA32_FIXED_CTR1 OverFlow
		ULONG64	CTR2OverFlow : 1;	 /// < [34] IA32_FIXED_CTR2 OverFlow
		ULONG64	Reserved2 : 27;		 /// < [61:35]
		ULONG64 OvfDSBuffer : 1;	 /// < [62]
		ULONG64 CondChgd : 1;		 /// < [63]
	}fields;
	ULONG64 all;
};
static_assert(sizeof(MSR_IA32_PERF_GLOBAL_STATUS_VERSION2) == 8, "Size check");


union MSR_IA32_DEBUGCTL
{
	struct
	{
		ULONG64 LBR : 1;				/// < [0]	 
		ULONG64 BTF : 1;				/// < [1] 
		ULONG64 Reserved1 : 4;			/// < [5:2]
		ULONG64	TR : 1;					/// < [6]  
		ULONG64	BTS : 1;				/// < [7]  
		ULONG64	BTINT : 1;				/// < [8]  
		ULONG64	BTS_OFF_OS : 1;			/// < [9]
		ULONG64 BTS_OFF_USR: 1;			/// < [10]
		ULONG64 FRZ_LBRS_ON_PMI : 1	;	/// < [11]
		ULONG64 FRZ_PERFMON_ON_PMI : 1; /// < [12]
		ULONG64 UNCORE_PMI_EN : 1;		/// < [13]
		ULONG64 SMM_FRZ : 1;			/// < [14]
		ULONG64 Reserved2 : 49;			/// < [63:15]
	}fields;	
	ULONG64 all;
};
static_assert(sizeof(MSR_IA32_DEBUGCTL) == 8, "Size check");

union MSR_IA32_PERF_GLOBAL_CTRL
{
	struct
	{
		ULONG64 EN_PC0 : 1;				/// < [0]	 
		ULONG64 EN_PC1 : 1;				/// < [1] 
		ULONG64 EN_PC2 : 1;				/// < [2]
		ULONG64	EN_PC3 : 1;				/// < [3]  
		ULONG64	Reserved : 28;			/// < [31:4]  
		ULONG64	EN_FC0 : 1;				/// < [32]  
		ULONG64	EN_FC1 : 1;				/// < [33]
		ULONG64 EN_FC2 : 1;				/// < [34] 
		ULONG64 Reserved2 : 29;			/// < [63:35]
	}fields;
	ULONG64 all;
};
static_assert(sizeof(MSR_IA32_PERF_GLOBAL_CTRL) == 8, "Size check");

/// See: MODEL-SPECIFIC REGISTERS (MSRS)
enum class Msr : unsigned int {
	Ia32ApicBase = 0x01B,

	Ia32FeatureControl = 0x03A, 
	Ia32PMCx = 0xC1,
	Ia32SysenterCs = 0x174,
	Ia32SysenterEsp = 0x175,
	Ia32SysenterEip = 0x176, 
	Ia32PerfEvtseLx = 0x186,
	Ia32Debugctl = 0x1D9,

	Ia32FixedCtrl0 = 0x309,
	Ia32FixedCtrl1 = 0x30A,
	Ia32FixedCtrl2 = 0x30B,
 	Ia32FixedCtrl  = 0x38D,
	Ia32PerfGlobalStatus  = 0x38E,	// allows software to query counter overflow conditions on any combination of fixed - function PMCs or general - purpose PMCs via a single RDMSR.
	Ia32PerfGlobalCtrl	  = 0x38F,	// allows software to enable/disable event counting of all or any combination of fixed - function PMCs(IA32_FIXED_CTRx) or any general - purpose PMCs via a single WRMSR.
	Ia32PerfGlobalOvfCtrl = 0x390,  // allows software to clear counter overflow conditions on any combination of fixed - function PMCs or general - purpose PMCs via a single WRMSR.
	
	Ia32VmxBasic = 0x480,
	Ia32VmxPinbasedCtls = 0x481,
	Ia32VmxProcBasedCtls = 0x482,
	Ia32VmxExitCtls = 0x483,
	Ia32VmxEntryCtls = 0x484,
	Ia32VmxMisc = 0x485,
	Ia32VmxCr0Fixed0 = 0x486,
	Ia32VmxCr0Fixed1 = 0x487,
	Ia32VmxCr4Fixed0 = 0x488,
	Ia32VmxCr4Fixed1 = 0x489,
	Ia32VmxVmcsEnum = 0x48A,
	Ia32VmxProcBasedCtls2 = 0x48B,
	Ia32VmxEptVpidCap = 0x48C,
	Ia32VmxTruePinbasedCtls = 0x48D,
	Ia32VmxTrueProcBasedCtls = 0x48E,
	Ia32VmxTrueExitCtls = 0x48F,
	Ia32VmxTrueEntryCtls = 0x490,
	Ia32VmxVmfunc = 0x491,

	Ia32Efer = 0xC0000080,
	Ia32Star = 0xC0000081,
	Ia32Lstar = 0xC0000082,

	Ia32Fmask = 0xC0000084,

	Ia32FsBase = 0xC0000100,
	Ia32GsBase = 0xC0000101,
	Ia32KernelGsBase = 0xC0000102,
	Ia32TscAux = 0xC0000103,
};