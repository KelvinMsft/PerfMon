#include <ntddk.h>
extern "C"
{
	void __stdcall AsmSysCallStub(ULONG64 OriginalAddress);
}