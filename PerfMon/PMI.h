#pragma once
#include <ntddk.h>

NTSTATUS RegisterPmiInterrupt();
NTSTATUS UnregisterPmiInterrupt();