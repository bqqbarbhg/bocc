#pragma once

#include <stdint.h>

inline bool IsPow2(uint32_t value)
{
	return value && (value & (value - 1)) == 0;
}

inline uint32_t AlignValue(uint32_t value, uint32_t alignment)
{
	return value + (alignment - value % alignment) % alignment;
}

inline uint32_t AlignValuePow2(uint32_t value, uint32_t alignment)
{
	Assert(alignment != 0 && IsPow2(alignment));
	uint32_t mask = alignment - 1;
	return value + ((alignment - (value & mask)) & mask);
}

