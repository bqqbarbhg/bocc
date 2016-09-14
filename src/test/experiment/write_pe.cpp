#include "prelude.h"
#include "test/experiment/coff_defs.h"
#include "base/core/endian.h"
#include "base/math/bit_math.h"
#include <string.h>
#include <stdio.h>
#include <time.h>

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
	StoreLE32(&dos.e_lfanew, peOffset);

	char *pos = buffer + peOffset;
	memcpy(pos, "PE\0\0", 4);
	pos += 4;

	coff_file_header &fh = *(coff_file_header*)pos;
	pos += sizeof(coff_file_header);
	StoreLE16(&fh.Machine, 0x8664);
	StoreLE16(&fh.NumberOfSections, 2);
	StoreLE32(&fh.TimeDateStamp, (uint32_t)time(NULL));
	StoreLE32(&fh.PointerToSymbolTable, 0);
	StoreLE32(&fh.NumberOfSymbols, 0);
	StoreLE16(&fh.SizeOfOptionalHeader, 112 + 16 * 8);
	StoreLE16(&fh.Characteristics, 0x0001 | 0x0002 | 0x0020);

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

				StoreLE32UV(idataPtr + idataOff, 0);
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
				StoreLE64UV(idataPtr + idataOff, idataBase + fi.HintNameOff);
				idataOff += 8;
			}
			StoreLE64UV(idataPtr + idataOff, 0);
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
			StoreLE32(&it[di].ImportLookupRva, d.ImportRva);
			StoreLE32(&it[di].TimeStamp, 0);
			StoreLE32(&it[di].ForwarderIndex, 0);
			StoreLE32(&it[di].NameRva, d.NameRva);
			StoreLE32(&it[di].ImportAddressRva, d.AddressRva);
		}

		StoreLE32(&it[numDlls].ImportLookupRva, 0);
		StoreLE32(&it[numDlls].TimeStamp, 0);
		StoreLE32(&it[numDlls].ForwarderIndex, 0);
		StoreLE32(&it[numDlls].NameRva, 0);
		StoreLE32(&it[numDlls].ImportAddressRva, 0);

		idataSize = idataOff;
	}

	{
		char *textPtr = buffer + textFilePtr;

		char code[] = "\x48\x83\xEC\x20\x48\xC7\xC1\x00\x00\x00\x00\xFF\x14\x25\xCD\xAB\x34\x12\x48\xC7\xC1\x00\x00\x00\x00\xFF\x14\x25\xCD\xAB\x34\x12\x48\x83\xC4\x20";
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
		StoreLE16(&opt.Magic, 0x20b);
		opt.MajorLinkerVersion = 11;
		opt.MinorLinkerVersion = 0;
		StoreLE32(&opt.SizeOfCode, textSize);
		StoreLE32(&opt.SizeOfInitializedData, idataSize);
		StoreLE32(&opt.SizeOfUninitializedData, 0);
		StoreLE32(&opt.AddressOfEntryPoint, entrypointAddr);
		StoreLE32(&opt.BaseOfCode, textBase);
	}

	{
		coff_optional_header1_64 &opt = *(coff_optional_header1_64*)pos;
		pos += sizeof(coff_optional_header1_64);
		StoreLE64(&opt.ImageBase, imageBase);
	}

	{
		coff_optional_header2 &opt = *(coff_optional_header2*)pos;
		pos += sizeof(coff_optional_header2);
		StoreLE32(&opt.SectionAlignment, 4096);
		StoreLE32(&opt.FileAlignment, 512);
		StoreLE16(&opt.MajorOperatingSystemVersion, 6);
		StoreLE16(&opt.MinorOperatingSystemVersion, 0);
		StoreLE16(&opt.MajorImageVersion, 0);
		StoreLE16(&opt.MinorImageVersion, 0);
		StoreLE16(&opt.MajorSubsystemVersion, 6);
		StoreLE16(&opt.MinorSubsystemVersion, 0);
		StoreLE32(&opt.Win32VersionValue, 0);
		StoreLE32(&opt.SizeOfImage, 4096*3);
		StoreLE32(&opt.SizeOfHeaders, 1024);
		StoreLE32(&opt.CheckSum, 0);
		StoreLE16(&opt.Subsystem, 3);
		StoreLE16(&opt.DllCharacteristics, 0);
	}

	{
		coff_optional_header3_64 &opt = *(coff_optional_header3_64*)pos;
		pos += sizeof(coff_optional_header3_64);
		StoreLE64(&opt.SizeOfStackReserve, 1024);
		StoreLE64(&opt.SizeOfStackCommit, 1024);
		StoreLE64(&opt.SizeOfHeapReserve, 1024);
		StoreLE64(&opt.SizeOfHeapCommit, 1024);
	}

	{
		coff_optional_header4 &opt = *(coff_optional_header4*)pos;
		pos += sizeof(coff_optional_header4);
		StoreLE32(&opt.LoaderFlags, 0);
		StoreLE32(&opt.NumberOfRvaAndSizes, 16);
	}

	// Export Table
	{
		coff_data_directory &dd = *(coff_data_directory*)pos;
		pos += sizeof(coff_data_directory);
		StoreLE32(&dd.VirtualAddress, 0);
		StoreLE32(&dd.Size, 0);
	}

	// Import Table
	{
		coff_data_directory &dd = *(coff_data_directory*)pos;
		pos += sizeof(coff_data_directory);
		StoreLE32(&dd.VirtualAddress, idataBase);
		StoreLE32(&dd.Size, idataSize);
	}

	// Resource Table
	{
		coff_data_directory &dd = *(coff_data_directory*)pos;
		pos += sizeof(coff_data_directory);
		StoreLE32(&dd.VirtualAddress, 0);
		StoreLE32(&dd.Size, 0);
	}

	// Exception Table
	{
		coff_data_directory &dd = *(coff_data_directory*)pos;
		pos += sizeof(coff_data_directory);
		StoreLE32(&dd.VirtualAddress, 0);
		StoreLE32(&dd.Size, 0);
	}

	// Certificate Table
	{
		coff_data_directory &dd = *(coff_data_directory*)pos;
		pos += sizeof(coff_data_directory);
		StoreLE32(&dd.VirtualAddress, 0);
		StoreLE32(&dd.Size, 0);
	}

	// Base Relocation Table
	{
		coff_data_directory &dd = *(coff_data_directory*)pos;
		pos += sizeof(coff_data_directory);
		StoreLE32(&dd.VirtualAddress, 0);
		StoreLE32(&dd.Size, 0);
	}

	// Debug
	{
		coff_data_directory &dd = *(coff_data_directory*)pos;
		pos += sizeof(coff_data_directory);
		StoreLE32(&dd.VirtualAddress, 0);
		StoreLE32(&dd.Size, 0);
	}

	// Architecture
	{
		coff_data_directory &dd = *(coff_data_directory*)pos;
		pos += sizeof(coff_data_directory);
		StoreLE32(&dd.VirtualAddress, 0);
		StoreLE32(&dd.Size, 0);
	}

	// Global Ptr
	{
		coff_data_directory &dd = *(coff_data_directory*)pos;
		pos += sizeof(coff_data_directory);
		StoreLE32(&dd.VirtualAddress, 0);
		StoreLE32(&dd.Size, 0);
	}

	// TLS Table
	{
		coff_data_directory &dd = *(coff_data_directory*)pos;
		pos += sizeof(coff_data_directory);
		StoreLE32(&dd.VirtualAddress, 0);
		StoreLE32(&dd.Size, 0);
	}

	// Load Config Table
	{
		coff_data_directory &dd = *(coff_data_directory*)pos;
		pos += sizeof(coff_data_directory);
		StoreLE32(&dd.VirtualAddress, 0);
		StoreLE32(&dd.Size, 0);
	}

	// Bound Import
	{
		coff_data_directory &dd = *(coff_data_directory*)pos;
		pos += sizeof(coff_data_directory);
		StoreLE32(&dd.VirtualAddress, 0);
		StoreLE32(&dd.Size, 0);
	}

	// IAT
	{
		coff_data_directory &dd = *(coff_data_directory*)pos;
		pos += sizeof(coff_data_directory);
		StoreLE32(&dd.VirtualAddress, idataIAT);
		StoreLE32(&dd.Size, idataIATSize);
	}

	// Delay Import Descriptor
	{
		coff_data_directory &dd = *(coff_data_directory*)pos;
		pos += sizeof(coff_data_directory);
		StoreLE32(&dd.VirtualAddress, 0);
		StoreLE32(&dd.Size, 0);
	}

	// CLR Runtime Header
	{
		coff_data_directory &dd = *(coff_data_directory*)pos;
		pos += sizeof(coff_data_directory);
		StoreLE32(&dd.VirtualAddress, 0);
		StoreLE32(&dd.Size, 0);
	}

	// Reserved
	{
		coff_data_directory &dd = *(coff_data_directory*)pos;
		pos += sizeof(coff_data_directory);
		StoreLE32(&dd.VirtualAddress, 0);
		StoreLE32(&dd.Size, 0);
	}

	{
		coff_section_header &sh = *(coff_section_header*)pos;
		pos += sizeof(coff_section_header);
		memcpy(sh.Name, ".text\0\0\0", 8);
		StoreLE32(&sh.Misc.VirtualSize, textSize);
		StoreLE32(&sh.VirtualAddress, textBase);
		StoreLE32(&sh.SizeOfRawData, textSize);
		StoreLE32(&sh.PointerToRawData, textFilePtr);
		StoreLE32(&sh.PointerToRelocations, 0);
		StoreLE32(&sh.PointerToLinenumbers, 0);
		StoreLE16(&sh.NumberOfRelocations, 0);
		StoreLE16(&sh.NumberOfLinenumbers, 0);
		StoreLE32(&sh.Characteristics, 0x20000000 | 0x40000000);
	}

	{
		coff_section_header &sh = *(coff_section_header*)pos;
		pos += sizeof(coff_section_header);
		memcpy(sh.Name, ".idata\0\0", 8);
		StoreLE32(&sh.Misc.VirtualSize, idataSize);
		StoreLE32(&sh.VirtualAddress, idataBase);
		StoreLE32(&sh.SizeOfRawData, idataSize);
		StoreLE32(&sh.PointerToRawData, idataFilePtr);
		StoreLE32(&sh.PointerToRelocations, 0);
		StoreLE32(&sh.PointerToLinenumbers, 0);
		StoreLE16(&sh.NumberOfRelocations, 0);
		StoreLE16(&sh.NumberOfLinenumbers, 0);
		StoreLE32(&sh.Characteristics, 0x80000000 | 0x40000000);
	}

	TestWriteFullFileToTemp("testbeep.exe", buffer, fileSize);

	free(buffer);
}

