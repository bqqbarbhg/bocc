#include "prelude.h"
#include "base/core/endian.h"
#include "base/math/bit_math.h"
#include <string.h>
#include <stdio.h>

struct elf_header0
{
	char e_ident[16];
	uint16_le e_type;
	uint16_le e_machine;
	uint32_le e_version;
};

struct elf_header1_32
{
	uint32_le e_entry;
	uint32_le e_phoff;
	uint32_le e_shoff;
};

struct elf_header1_64
{
	uint64_le e_entry;
	uint64_le e_phoff;
	uint64_le e_shoff;
};

struct elf_header2
{
	uint32_le e_flags;
	uint16_le e_ehsize;
	uint16_le e_phentsize;
	uint16_le e_phnum;
	uint16_le e_shentsize;
	uint16_le e_shnum;
	uint16_le e_shstrndx;
};

struct elf_program_header_32
{
	uint32_le p_type;
	uint32_le p_offset;
	uint32_le p_vaddr;
	uint32_le p_paddr;
	uint32_le p_filesz;
	uint32_le p_memsz;
	uint32_le p_flags;
	uint32_le p_align;
};

struct elf_program_header_64
{
	uint32_le p_type;
	uint32_le p_flags;
	uint64_le p_offset;
	uint64_le p_vaddr;
	uint64_le p_paddr;
	uint64_le p_filesz;
	uint64_le p_memsz;
	uint64_le p_align;
};

struct elf_section_header_32
{
	uint32_le sh_name;
	uint32_le sh_type;
	uint32_le sh_flags;
	uint32_le sh_addr;
	uint32_le sh_offset;
	uint32_le sh_size;
	uint32_le sh_link;
	uint32_le sh_info;
	uint32_le sh_addralign;
	uint32_le sh_entsize;
};

struct elf_section_header_64
{
	uint32_le sh_name;
	uint32_le sh_type;
	uint64_le sh_flags;
	uint64_le sh_addr;
	uint64_le sh_offset;
	uint64_le sh_size;
	uint32_le sh_link;
	uint32_le sh_info;
	uint64_le sh_addralign;
	uint64_le sh_entsize;
};

TestCase(ExperimentWriteSimpleELF)
{
	char *buffer = (char*)calloc(4096, 4);

	// Note: Base addresses below 0x10000 seem to crash at startup
	uint32_t imageBase = 0x40000;
	uint32_t entryPoint = 0;

	uint32_t fileProgramHeaderOff = 0x40;
	uint32_t codeFilePtr = 4096;
	uint32_t codeFileSize = 0;

	uint32_t fileSize = 4096 * 2;

	{
		char code[] = "\x48\xC7\xC0\x01\x00\x00\x00\x48\xC7\xC7\x01\x00\x00\x00\x48\x8D\x35\x32\x00\x00\x00\x48\xC7\xC2\x0A\x00\x00\x00\x0F\x05\x48\xC7\xC0\x3C\x00\x00\x00\x48\x31\xFF\x0F\x05";

		uint32_t locMsgPtr = 0x0e + 3;
		uint32_t locMsgLen = 0x15 + 3;

		const char message[] = "Hello world!\n";

		uint32_t msgOff = sizeof(code) - locMsgPtr - 4;
		*(uint32_t*)(code + locMsgPtr) = msgOff;
		*(uint32_t*)(code + locMsgLen) = sizeof(message) - 1;

		char *codeStart = buffer + codeFilePtr;
		char *pos = codeStart;

		memcpy(pos, code, sizeof(code));
		pos += sizeof(code);
		memcpy(pos, message, sizeof(message));
		pos += sizeof(message);

		codeFileSize = pos - codeStart;
	}

	char *pos = buffer;
	{
		elf_header0 &eh = *(elf_header0*)pos;
		pos += sizeof(elf_header0);

		memcpy(eh.e_ident, "\x7f" "ELF", 4);
		eh.e_ident[4] = 2;
		eh.e_ident[5] = 1;
		eh.e_ident[6] = 1;
		memset(eh.e_ident + 7, 0, 9);
		StoreLE16(&eh.e_type, 2);
		StoreLE16(&eh.e_machine, 0x3E);
		StoreLE32(&eh.e_version, 1);
	}

	{
		elf_header1_64 &eh = *(elf_header1_64*)pos;
		pos += sizeof(elf_header1_64);
		StoreLE64(&eh.e_entry, imageBase + entryPoint);
		StoreLE64(&eh.e_phoff, fileProgramHeaderOff);
		StoreLE64(&eh.e_shoff, 0);
	}

	{
		elf_header2 &eh = *(elf_header2*)pos;
		pos += sizeof(elf_header2);
		StoreLE32(&eh.e_flags, 0);
		StoreLE16(&eh.e_ehsize, 0x40);
		StoreLE16(&eh.e_phentsize, sizeof(elf_program_header_64));
		StoreLE16(&eh.e_phnum, 1);
		StoreLE16(&eh.e_shentsize, sizeof(elf_section_header_64));
		StoreLE16(&eh.e_shnum, 0);
		StoreLE16(&eh.e_shstrndx, 0);
	}

	{
		elf_program_header_64 &ph = *(elf_program_header_64*)(buffer + fileProgramHeaderOff);
		StoreLE32(&ph.p_type, 1);
		StoreLE64(&ph.p_offset, codeFilePtr);
		StoreLE64(&ph.p_vaddr, imageBase + 0);
		StoreLE64(&ph.p_paddr, 0);
		StoreLE64(&ph.p_filesz, codeFileSize);
		StoreLE64(&ph.p_memsz, codeFileSize);
		StoreLE32(&ph.p_flags, 0x1|0x2|0x4);
		StoreLE64(&ph.p_align, 4096);
	}

	TestWriteFullFileToTemp("helloworld.elf", buffer, fileSize);
	free(buffer);
}

