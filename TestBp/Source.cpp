#include "stdafx.h"
#include "Windows.h"

int main() 
{
	for (int i = 0; i < 100; i++)
	{
		__try
		{
			SetThreadAffinityMask(GetCurrentThread(), 1);
			DebugBreak();
		}
		__except (1)
		{

		}
	}
	return 0;
}