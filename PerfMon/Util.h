#pragma once
#include<ntddk.h>

NTSTATUS UtilForEachProcessor(NTSTATUS(*callback_routine)(void *), void *context);