#pragma once
#include<ntddk.h>

extern "C" { 
	void*	 UtilGetSystemProcAddress(
		_In_ const wchar_t *proc_name
	);
	
	NTSTATUS UtilForEachProcessor(
		_In_ NTSTATUS(*callback_routine)(void *), 
		_In_ void *context
	);
}