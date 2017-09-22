
#include <ntddk.h>

// Execute a given callback routine on all processors in DPC_LEVEL. Returns
// STATUS_SUCCESS when all callback returned STATUS_SUCCESS as well. When
// one of callbacks returns anything but STATUS_SUCCESS, this function stops
// to call remaining callbacks and returns the value.
NTSTATUS UtilForEachProcessor(
	_In_ NTSTATUS(*callback_routine)(void *), 
	_In_ void *context) 
{
	const auto number_of_processors =
		KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
	for (ULONG processor_index = 0; processor_index < number_of_processors;processor_index++) 
	{
		PROCESSOR_NUMBER processor_number = {};
		auto status = KeGetProcessorNumberFromIndex(processor_index, &processor_number);
		if (!NT_SUCCESS(status)) 
		{
			return status;
		}

		// Switch the current processor
		GROUP_AFFINITY affinity = {};
		affinity.Group = processor_number.Group;
		affinity.Mask = 1ull << processor_number.Number;
		GROUP_AFFINITY previous_affinity = {};
		KeSetSystemGroupAffinityThread(&affinity, &previous_affinity);

		// Execute callback
		status = callback_routine(context);

		KeRevertToUserGroupAffinityThread(&previous_affinity);
		if (!NT_SUCCESS(status)) 
		{
			return status;
		}
	}
	return STATUS_SUCCESS;
}