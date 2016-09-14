#pragma once

#if 1

typedef union {
	uint16_t ValueForAlignment;
	uint8_t Bytes[2];
} uint16_le;

typedef union {
	uint32_t ValueForAlignment;
	uint8_t Bytes[4];
} uint32_le;

typedef union {
	uint64_t ValueForAlignment;
	uint8_t Bytes[8];
} uint64_le;

typedef struct {
	uint8_t Bytes[2];
} uint16_unaligned_le;

typedef struct {
	uint8_t Bytes[4];
} uint32_unaligned_le;

typedef struct {
	uint8_t Bytes[8];
} uint64_unaligned_le;

inline uint16_t LoadLE16U(const uint16_unaligned_le *ptr)
{
	uint16_t val = 0;
	for (int byte = 0; byte < 2; byte++)
		val |= (uint16_t)ptr->Bytes[byte] << (8 * byte);
	return val;
}

inline uint32_t LoadLE32U(const uint32_unaligned_le *ptr)
{
	uint32_t val = 0;
	for (int byte = 0; byte < 4; byte++)
		val |= (uint32_t)ptr->Bytes[byte] << (8 * byte);
	return val;
}

inline uint64_t LoadLE64U(const uint64_unaligned_le *ptr)
{
	uint64_t val = 0;
	for (int byte = 0; byte < 8; byte++)
		val |= (uint64_t)ptr->Bytes[byte] << (8 * byte);
	return val;
}

inline void StoreLE16U(uint16_unaligned_le *ptr, uint16_t val)
{
	for (int byte = 0; byte < 2; byte++)
		ptr->Bytes[byte] = (uint8_t)((val >> (8 * byte)) & 0xFF);
}

inline void StoreLE32U(uint32_unaligned_le *ptr, uint32_t val)
{
	for (int byte = 0; byte < 4; byte++)
		ptr->Bytes[byte] = (uint8_t)((val >> (8 * byte)) & 0xFF);
}

inline void StoreLE64U(uint64_unaligned_le *ptr, uint64_t val)
{
	for (int byte = 0; byte < 8; byte++)
		ptr->Bytes[byte] = (uint8_t)((val >> (8 * byte)) & 0xFF);
}

inline uint16_t LoadLE16(const uint16_le *ptr)
{
	Assert((uintptr_t)ptr % 2 == 0);
	return LoadLE16U((const uint16_unaligned_le*)ptr);
}

inline uint32_t LoadLE32(const uint32_le *ptr)
{
	Assert((uintptr_t)ptr % 4 == 0);
	return LoadLE32U((const uint32_unaligned_le*)ptr);
}

inline uint64_t LoadLE64(const uint64_le *ptr)
{
	Assert((uintptr_t)ptr % 8 == 0);
	return LoadLE64U((const uint64_unaligned_le*)ptr);
}

inline void StoreLE16(uint16_le *ptr, uint16_t val)
{
	Assert((uintptr_t)ptr % 2 == 0);
	StoreLE16U((uint16_unaligned_le*)ptr, val);
}

inline void StoreLE32(uint32_le *ptr, uint32_t val)
{
	Assert((uintptr_t)ptr % 4 == 0);
	StoreLE32U((uint32_unaligned_le*)ptr, val);
}

inline void StoreLE64(uint64_le *ptr, uint64_t val)
{
	Assert((uintptr_t)ptr % 8 == 0);
	StoreLE64U((uint64_unaligned_le*)ptr, val);
}

#else

typedef struct {
	uint16_t Value;
} uint16_le;

typedef struct {
	uint32_t Value;
} uint32_le;

typedef struct {
	uint64_t Value;
} uint64_le;

typedef struct {
	uint8_t Bytes[2];
} uint16_unaligned_le;

typedef struct {
	uint8_t Bytes[4];
} uint32_unaligned_le;

typedef struct {
	uint8_t Bytes[8];
} uint64_unaligned_le;

inline uint16_t LoadLE16U(const uint16_unaligned_le *ptr)
{
	return *(uint16_t*)ptr->Bytes;
}

inline uint32_t LoadLE32U(const uint32_unaligned_le *ptr)
{
	return *(uint32_t*)ptr->Bytes;
}

inline uint64_t LoadLE64U(const uint64_unaligned_le *ptr)
{
	return *(uint64_t*)ptr->Bytes;
}

inline void StoreLE16U(uint16_unaligned_le *ptr, uint16_t val)
{
	*(uint16_t*)ptr->Bytes = val;
}

inline void StoreLE32U(uint32_unaligned_le *ptr, uint32_t val)
{
	*(uint32_t*)ptr->Bytes = val;
}

inline void StoreLE64U(uint64_unaligned_le *ptr, uint64_t val)
{
	*(uint64_t*)ptr->Bytes = val;
}

inline uint16_t LoadLE16(const uint16_le *ptr)
{
	return ptr->Value;
}

inline uint32_t LoadLE32(const uint32_le *ptr)
{
	return ptr->Value;
}

inline uint64_t LoadLE64(const uint64_le *ptr)
{
	return ptr->Value;
}

inline void StoreLE16(uint16_le *ptr, uint16_t val)
{
	ptr->Value = val;
}

inline void StoreLE32(uint32_le *ptr, uint32_t val)
{
	ptr->Value = val;
}

inline void StoreLE64(uint64_le *ptr, uint64_t val)
{
	ptr->Value = val;
}

#endif

inline uint16_t LoadLE16UV(const void *ptr)
{
	return LoadLE16U((uint16_unaligned_le*)ptr);
}

inline uint32_t LoadLE32UV(const void *ptr)
{
	return LoadLE32U((uint32_unaligned_le*)ptr);
}

inline uint64_t LoadLE64UV(const void *ptr)
{
	return LoadLE64U((uint64_unaligned_le*)ptr);
}

inline void StoreLE16UV(void *ptr, uint16_t val)
{
	StoreLE16U((uint16_unaligned_le*)ptr, val);
}

inline void StoreLE32UV(void *ptr, uint32_t val)
{
	StoreLE32U((uint32_unaligned_le*)ptr, val);
}

inline void StoreLE64UV(void *ptr, uint64_t val)
{
	StoreLE64U((uint64_unaligned_le*)ptr, val);
}


