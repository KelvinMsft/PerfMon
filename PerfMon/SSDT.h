#include <ntddk.h> 

#pragma pack(push , 1)
typedef struct _SYSTEM_SERVICE_TABLE {
	PVOID       ServiceTableBase;
	PVOID       ServiceCounterTableBase;
	ULONGLONG   NumberOfServices;
	PVOID       ParamTableBase;
} SYSTEM_SERVICE_TABLE, *PSYSTEM_SERVICE_TABLE;
#pragma pack(pop)

#pragma pack(push , 1)
	typedef struct
	{
		UCHAR    FixCode[6];
		ULONG64  JmpAddr;
	}JMPCODE;
#pragma pack(pop)
	  
EXTERN_C NTSTATUS InitSSDTHook();
EXTERN_C NTSTATUS UninitSSDTHook();
EXTERN_C VOID  SyscallHandler(PKTRAP_FRAME pTrapFrame);
EXTERN_C ULONG GetOffsetAddress(PULONG SSDTBase, ULONGLONG FuncAddr, CHAR paramCount);
EXTERN_C void* GetSSDTProcAddress(void* SSTD, ULONG Index, PULONG lpParamCount);
