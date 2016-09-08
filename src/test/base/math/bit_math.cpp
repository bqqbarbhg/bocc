#include "prelude.h"

#include "base/math/bit_math.h"
#include "test/test_support.h"

TestCase(IsPow2)
{
	for (uint32_t i = 0; i < 10000; i++)
	{
		bool isPow2 = false;
		for (uint32_t j = 0; j < 32; j++)
		{
			if (1 << j == i)
			{
				isPow2 = true;
				break;
			}
		}

		TestAssert(IsPow2(i) == isPow2);
	}
}

TestCase(AlignValue)
{
	for (uint32_t align = 1; align < 32; align++)
	{
		for (uint32_t value = 0; value < 1024; value++)
		{
			uint32_t aligned = AlignValue(value, align);

			TestAssert(aligned >= value);
			TestAssert(aligned % align == 0);
			TestAssert(aligned - value < align);
		}
	}
}

TestCase(AlignValuePow2)
{
	for (uint32_t align = 1; align < 32; align <<= 1)
	{
		for (uint32_t value = 0; value < 1024; value++)
		{
			uint32_t aligned = AlignValuePow2(value, align);

			TestAssert(aligned >= value);
			TestAssert(aligned % align == 0);
			TestAssert(aligned - value < align);
		}
	}
}

