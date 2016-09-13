#pragma once

#include "base/core/endian.h"

struct pe_dos_header 
{
	uint8_t signature[2];
	uint16_le lastsize;
	uint16_le nblocks;
	uint16_le nreloc;
	uint16_le hdrsize;
	uint16_le minalloc;
	uint16_le maxalloc;
	uint16_le ss;
	uint16_le sp;
	uint16_le checksum;
	uint16_le ip;
	uint16_le cs;
	uint16_le relocpos;
	uint16_le noverlay;
	uint16_t reserved1[4];
	uint16_le oem_id;
	uint16_le oem_info;
	uint16_t reserved2[10];
	uint32_le  e_lfanew;
};

struct coff_data_directory
{
	uint32_le VirtualAddress;
	uint32_le Size;
};

struct coff_file_header
{
	uint16_le Machine;
	uint16_le NumberOfSections;
	uint32_le TimeDateStamp;
	uint32_le PointerToSymbolTable;
	uint32_le NumberOfSymbols;
	uint16_le SizeOfOptionalHeader;
	uint16_le Characteristics;
};

struct coff_import_header
{
	uint16_le Sig1;
	uint16_le Sig2;
	uint16_le Version;
	uint16_le Machine;
	uint32_le TimeDateStamp;
	uint32_le SizeOfData;
	uint16_le OrdinalOrHint;
	uint16_le Type;
};

struct coff_optional_header0
{
	uint16_le Magic;
	uint8_t MajorLinkerVersion;
	uint8_t MinorLinkerVersion;
	uint32_le SizeOfCode;
	uint32_le SizeOfInitializedData;
	uint32_le SizeOfUninitializedData;
	uint32_le AddressOfEntryPoint;
	uint32_le BaseOfCode;
};

struct coff_optional_header1_32
{
	uint32_le BaseOfData;
	uint32_le ImageBase;
};

struct coff_optional_header1_64
{
	uint64_le ImageBase;
};

struct coff_optional_header2
{
	uint32_le SectionAlignment;
	uint32_le FileAlignment;
	uint16_le MajorOperatingSystemVersion;
	uint16_le MinorOperatingSystemVersion;
	uint16_le MajorImageVersion;
	uint16_le MinorImageVersion;
	uint16_le MajorSubsystemVersion;
	uint16_le MinorSubsystemVersion;
	uint32_le Win32VersionValue;
	uint32_le SizeOfImage;
	uint32_le SizeOfHeaders;
	uint32_le CheckSum;
	uint16_le Subsystem;
	uint16_le DllCharacteristics;
};

struct coff_optional_header3_32
{
	uint32_le SizeOfStackReserve;
	uint32_le SizeOfStackCommit;
	uint32_le SizeOfHeapReserve;
	uint32_le SizeOfHeapCommit;
};

struct coff_optional_header3_64
{
	uint64_le SizeOfStackReserve;
	uint64_le SizeOfStackCommit;
	uint64_le SizeOfHeapReserve;
	uint64_le SizeOfHeapCommit;
};

struct coff_optional_header4
{
	uint32_le LoaderFlags;
	uint32_le NumberOfRvaAndSizes;
};

struct coff_section_header
{
	uint8_t Name[8];
	union {
		uint32_le PhysicalAddress;
		uint32_le VirtualSize;
	} Misc;
	uint32_le VirtualAddress;
	uint32_le SizeOfRawData;
	uint32_le PointerToRawData;
	uint32_le PointerToRelocations;
	uint32_le PointerToLinenumbers;
	uint16_le NumberOfRelocations;
	uint16_le NumberOfLinenumbers;
	uint32_le Characteristics;
};

struct coff_import_directory_table
{
	uint32_le ImportLookupRva;
	uint32_le TimeStamp;
	uint32_le ForwarderIndex;
	uint32_le NameRva;
	uint32_le ImportAddressRva;
};

struct coff_symbol
{
	union
	{
		struct 
		{
			uint32_unalgined_le Zeroes;
			uint32_unalgined_le StringIndex;
		} Long;
		uint8_t Short[8];
	} Name;

	uint32_unalgined_le Value;
	uint16_unalgined_le SectionNumber;
	uint16_unalgined_le Type;
	uint8_t StorageClass;
	uint8_t NumberOfAuxSymbols;
};

struct coff_relocation
{
	uint32_unalgined_le VirtualAddress;
	uint32_unalgined_le SymbolTableIndex;
	uint16_unalgined_le Type;
};
