#include "prelude.h"
#include "base/core/endian.h"
#include "base/math/bit_math.h"
#include <string.h>
#include <stdio.h>
#include <time.h>

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

struct func_import
{
	const char *Name;
	uint32_t HintNameOff;
	uint32_t Rva;
};

struct dll_import
{
	const char *Name;
	func_import *Imports;
	uint32_t NumImports;

	uint32_t ImportRva;
	uint32_t AddressRva;
	uint32_t NameRva;
};

TestCase(ExperimentWriteSimplePE)
{
	char *buffer = (char*)calloc(4096, 4);

	uint32_t imageBase = 0x00400000;

	uint32_t textBase = 4096 * 1;
	uint32_t idataBase = 4096 * 2;
	uint32_t fileSize = 4096 * 3;

	uint32_t idataIAT = 0, idataIATSize = 0;

	uint32_t idataFilePtr = 512 * 2;
	uint32_t textFilePtr = 512 * 3;

	uint32_t entrypointAddr = 0;

	uint32_t textSize = 0;
	uint32_t idataSize = 0;

	uint32_t peOffset = AlignValuePow2(sizeof(pe_dos_header) + 32, 8);

	uint32_t importBeepAddr = 0;

	pe_dos_header &dos = *(pe_dos_header*)buffer;
	dos.signature[0] = 'M';
	dos.signature[1] = 'Z';
	dos.e_lfanew = peOffset;

	char *pos = buffer + peOffset;
	memcpy(pos, "PE\0\0", 4);
	pos += 4;

	coff_file_header &fh = *(coff_file_header*)pos;
	pos += sizeof(coff_file_header);
	fh.Machine = 0x8664;
	fh.NumberOfSections = 2;
	fh.TimeDateStamp = (uint32_t)time(NULL);
	fh.PointerToSymbolTable = 0;
	fh.NumberOfSymbols = 0;
	fh.SizeOfOptionalHeader = 112 + 16 * 8;
	fh.Characteristics = 0x0001 | 0x0002 | 0x0020;

	func_import funcs[2];
	funcs[0].Name = "MessageBeep";
	funcs[1].Name = "ExitProcess";

	dll_import dlls[2];
	dlls[0].Name = "user32.dll";
	dlls[0].Imports = funcs;
	dlls[0].NumImports = 1;

	dlls[1].Name = "kernel32.dll";
	dlls[1].Imports = funcs + 1;
	dlls[1].NumImports = 1;

	uint32_t numDlls = 2;

	{
		char *idataPtr = buffer + idataFilePtr;
		char *idataStartPtr = idataPtr;

		uint32_t idataOff = sizeof(coff_import_directory_table) * (numDlls + 1);

		idataOff = AlignValuePow2(idataOff, 16);

		for (uint32_t di = 0; di < numDlls; di++)
		{
			dll_import &d = dlls[di];
			for (uint32_t ii = 0; ii < d.NumImports; ii++)
			{
				func_import &fi = d.Imports[ii];
				uint32_t importNameLen = (uint32_t)strlen(fi.Name);
				fi.HintNameOff = idataOff;

				WriteAligned16LE(idataPtr + idataOff, 0);
				idataOff += 2;
				memcpy(idataPtr + idataOff, fi.Name, importNameLen + 1);
				idataOff += importNameLen;
				if (idataOff % 2 == 1)
				{
					idataPtr[idataOff] = '\0';
					idataOff++;
				}
			}
		}

		idataOff = AlignValuePow2(idataOff, 8);

		uint32_t importLookupOff = idataOff;

		for (uint32_t di = 0; di < numDlls; di++)
		{
			dll_import &d = dlls[di];
			d.ImportRva = idataBase + idataOff;
			for (uint32_t ii = 0; ii < d.NumImports; ii++)
			{
				func_import &fi = d.Imports[ii];
				WriteAligned64LE(idataPtr + idataOff, idataBase + fi.HintNameOff);
				idataOff += 8;
			}
			WriteAligned64LE(idataPtr + idataOff, 0);
			idataOff += 8;
		}

		uint32_t importLookupSize = idataOff - importLookupOff;

		uint32_t importAddressOff = idataOff;
		idataIAT = idataBase + importAddressOff;

		memcpy(idataPtr + idataOff, idataPtr + importLookupOff, importLookupSize);

		for (uint32_t di = 0; di < numDlls; di++)
		{
			dll_import &d = dlls[di];
			d.AddressRva = idataBase + idataOff;
			for (uint32_t ii = 0; ii < d.NumImports; ii++)
			{
				func_import &fi = d.Imports[ii];
				fi.Rva = idataBase + idataOff;
				idataOff += 8;
			}
			idataOff += 8;
		}

		idataOff += importLookupSize;
		idataIATSize = importLookupSize;

		idataOff = AlignValuePow2(idataOff, 8);

		for (uint32_t di = 0; di < numDlls; di++)
		{
			dll_import &d = dlls[di];
			d.NameRva = idataBase + idataOff;

			uint32_t dllNameLen = (uint32_t)strlen(d.Name);
			memcpy(idataPtr + idataOff, d.Name, dllNameLen + 1);
			idataOff += dllNameLen + 1;
		}

		idataOff = AlignValuePow2(idataOff, 8);

		coff_import_directory_table *it = (coff_import_directory_table*)idataStartPtr;

		for (uint32_t di = 0; di < numDlls; di++)
		{
			dll_import &d = dlls[di];
			it[di].ImportLookupRva = d.ImportRva;
			it[di].TimeStamp = 0;
			it[di].ForwarderIndex = 0;
			it[di].NameRva = d.NameRva;
			it[di].ImportAddressRva = d.AddressRva;
		}

		it[numDlls].ImportLookupRva = 0;
		it[numDlls].TimeStamp = 0;
		it[numDlls].ForwarderIndex = 0;
		it[numDlls].NameRva = 0;
		it[numDlls].ImportAddressRva = 0;

		idataSize = idataOff;
	}

	{
		char *textPtr = buffer + textFilePtr;

		const char code[] = "\x48\x83\xEC\x20\x48\xC7\xC1\x00\x00\x00\x00\xFF\x14\x25\xCD\xAB\x34\x12\x48\xC7\xC1\x00\x00\x00\x00\xFF\x14\x25\xCD\xAB\x34\x12\x48\x83\xC4\x20";
		uint32_t codeLen = sizeof(code);

		{
			const char *patch = code + 0x0b + 3;
			*(uint32_t*)patch = imageBase + funcs[0].Rva;
		}

		{
			const char *patch = code + 0x19 + 3;
			*(uint32_t*)patch = imageBase + funcs[1].Rva;
		}

		uint32_t textOff = 32;

		entrypointAddr = textOff + textBase;
		memcpy(textPtr + textOff, code, codeLen);
		textOff += codeLen;

		textSize = textOff;
	}

	{
		coff_optional_header0 &opt = *(coff_optional_header0*)pos;
		pos += sizeof(coff_optional_header0);
		opt.Magic = 0x20b;
		opt.MajorLinkerVersion = 11;
		opt.MinorLinkerVersion = 0;
		opt.SizeOfCode = textSize;
		opt.SizeOfInitializedData = idataSize;
		opt.SizeOfUninitializedData = 0;
		opt.AddressOfEntryPoint = entrypointAddr;
		opt.BaseOfCode = textBase;
	}

	{
		coff_optional_header1_64 &opt = *(coff_optional_header1_64*)pos;
		pos += sizeof(coff_optional_header1_64);
		opt.ImageBase = imageBase;
	}

	{
		coff_optional_header2 &opt = *(coff_optional_header2*)pos;
		pos += sizeof(coff_optional_header2);
		opt.SectionAlignment = 4096;
		opt.FileAlignment = 512;
		opt.MajorOperatingSystemVersion = 6;
		opt.MinorOperatingSystemVersion = 0;
		opt.MajorImageVersion = 0;
		opt.MinorImageVersion = 0;
		opt.MajorSubsystemVersion = 6;
		opt.MinorSubsystemVersion = 0;
		opt.Win32VersionValue = 0;
		opt.SizeOfImage = 4096*3;
		opt.SizeOfHeaders = 1024;
		opt.CheckSum = 0;
		opt.Subsystem = 3;
		opt.DllCharacteristics = 0;
	}

	{
		coff_optional_header3_64 &opt = *(coff_optional_header3_64*)pos;
		pos += sizeof(coff_optional_header3_64);
		opt.SizeOfStackReserve = 1024;
		opt.SizeOfStackCommit = 1024;
		opt.SizeOfHeapReserve = 1024;
		opt.SizeOfHeapCommit = 1024;
	}

	{
		coff_optional_header4 &opt = *(coff_optional_header4*)pos;
		pos += sizeof(coff_optional_header4);
		opt.LoaderFlags = 0;
		opt.NumberOfRvaAndSizes = 16;
	}

	// Export Table
	{
		coff_data_directory &dd = *(coff_data_directory*)pos;
		pos += sizeof(coff_data_directory);
		dd.VirtualAddress = 0;
		dd.Size = 0;
	}

	// Import Table
	{
		coff_data_directory &dd = *(coff_data_directory*)pos;
		pos += sizeof(coff_data_directory);
		dd.VirtualAddress = idataBase;
		dd.Size = idataSize;
	}

	// Resource Table
	{
		coff_data_directory &dd = *(coff_data_directory*)pos;
		pos += sizeof(coff_data_directory);
		dd.VirtualAddress = 0;
		dd.Size = 0;
	}

	// Exception Table
	{
		coff_data_directory &dd = *(coff_data_directory*)pos;
		pos += sizeof(coff_data_directory);
		dd.VirtualAddress = 0;
		dd.Size = 0;
	}

	// Certificate Table
	{
		coff_data_directory &dd = *(coff_data_directory*)pos;
		pos += sizeof(coff_data_directory);
		dd.VirtualAddress = 0;
		dd.Size = 0;
	}

	// Base Relocation Table
	{
		coff_data_directory &dd = *(coff_data_directory*)pos;
		pos += sizeof(coff_data_directory);
		dd.VirtualAddress = 0;
		dd.Size = 0;
	}

	// Debug
	{
		coff_data_directory &dd = *(coff_data_directory*)pos;
		pos += sizeof(coff_data_directory);
		dd.VirtualAddress = 0;
		dd.Size = 0;
	}

	// Architecture
	{
		coff_data_directory &dd = *(coff_data_directory*)pos;
		pos += sizeof(coff_data_directory);
		dd.VirtualAddress = 0;
		dd.Size = 0;
	}

	// Global Ptr
	{
		coff_data_directory &dd = *(coff_data_directory*)pos;
		pos += sizeof(coff_data_directory);
		dd.VirtualAddress = 0;
		dd.Size = 0;
	}

	// TLS Table
	{
		coff_data_directory &dd = *(coff_data_directory*)pos;
		pos += sizeof(coff_data_directory);
		dd.VirtualAddress = 0;
		dd.Size = 0;
	}

	// Load Config Table
	{
		coff_data_directory &dd = *(coff_data_directory*)pos;
		pos += sizeof(coff_data_directory);
		dd.VirtualAddress = 0;
		dd.Size = 0;
	}

	// Bound Import
	{
		coff_data_directory &dd = *(coff_data_directory*)pos;
		pos += sizeof(coff_data_directory);
		dd.VirtualAddress = 0;
		dd.Size = 0;
	}

	// IAT
	{
		coff_data_directory &dd = *(coff_data_directory*)pos;
		pos += sizeof(coff_data_directory);
		dd.VirtualAddress = idataIAT;
		dd.Size = idataIATSize;
	}

	// Delay Import Descriptor
	{
		coff_data_directory &dd = *(coff_data_directory*)pos;
		pos += sizeof(coff_data_directory);
		dd.VirtualAddress = 0;
		dd.Size = 0;
	}

	// CLR Runtime Header
	{
		coff_data_directory &dd = *(coff_data_directory*)pos;
		pos += sizeof(coff_data_directory);
		dd.VirtualAddress = 0;
		dd.Size = 0;
	}

	// Reserved
	{
		coff_data_directory &dd = *(coff_data_directory*)pos;
		pos += sizeof(coff_data_directory);
		dd.VirtualAddress = 0;
		dd.Size = 0;
	}

	{
		coff_section_header &sh = *(coff_section_header*)pos;
		pos += sizeof(coff_section_header);
		memcpy(sh.Name, ".text\0\0\0", 8);
		sh.Misc.VirtualSize = textSize;
		sh.VirtualAddress = textBase;
		sh.SizeOfRawData = textSize;
		sh.PointerToRawData = textFilePtr;
		sh.PointerToRelocations = 0;
		sh.PointerToLinenumbers = 0;
		sh.NumberOfRelocations = 0;
		sh.NumberOfLinenumbers = 0;
		sh.Characteristics = 0x20000000 | 0x40000000;
	}

	{
		coff_section_header &sh = *(coff_section_header*)pos;
		pos += sizeof(coff_section_header);
		memcpy(sh.Name, ".idata\0\0", 8);
		sh.Misc.VirtualSize = idataSize;
		sh.VirtualAddress = idataBase;
		sh.SizeOfRawData = idataSize;
		sh.PointerToRawData = idataFilePtr;
		sh.PointerToRelocations = 0;
		sh.PointerToLinenumbers = 0;
		sh.NumberOfRelocations = 0;
		sh.NumberOfLinenumbers = 0;
		sh.Characteristics = 0x80000000 | 0x40000000;
	}

	char path[256];
	sprintf(path, "%stestbeep.exe", GetTestTempDirectory());

	FILE *outf = fopen(path, "wb");

	fwrite(buffer, 1, fileSize, outf);
	fclose(outf);

	free(buffer);
}

