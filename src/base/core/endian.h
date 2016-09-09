#pragma once

inline void WriteAligned16LE(void *ptr, uint16_t value)
{
	Assert((uintptr_t)ptr % 2 == 0);
	*(uint16_t*)ptr = value;
}

inline void WriteAligned32LE(void *ptr, uint32_t value)
{
	Assert((uintptr_t)ptr % 4 == 0);
	*(uint32_t*)ptr = value;
}

inline void WriteAligned64LE(void *ptr, uint64_t value)
{
	Assert((uintptr_t)ptr % 8 == 0);
	*(uint64_t*)ptr = value;
}

struct uint16_le
{
	uint16_t InnerValue;

	uint16_le& operator=(uint16_t val)
	{
		InnerValue = val;
		return *this;
	}

	operator uint16_t()
	{
		return InnerValue;
	}
};

struct uint32_le
{
	uint32_t InnerValue;

	uint32_le& operator=(uint32_t val)
	{
		InnerValue = val;
		return *this;
	}

	operator uint32_t()
	{
		return InnerValue;
	}
};

struct uint64_le
{
	uint64_t InnerValue;

	uint64_le& operator=(uint64_t val)
	{
		InnerValue = val;
		return *this;
	}

	operator uint64_t()
	{
		return InnerValue;
	}
};

