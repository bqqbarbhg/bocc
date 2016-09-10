
enum coff_section_characteristics
{
	IMAGE_SCN_TYPE_NO_PAD = 0x00000008, // The section should not be padded to the next boundary. This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES. This is valid only for object files.
	IMAGE_SCN_CNT_CODE = 0x00000020, // The section contains executable code.
	IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040, // The section contains initialized data.
	IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080 //The section contains uninitialized data.
	IMAGE_SCN_LNK_OTHER = 0x00000100, // Reserved for future use.
	IMAGE_SCN_LNK_INFO = 0x00000200, // The section contains comments or other information. The .drectve section has this type. This is valid for object files only.
	IMAGE_SCN_LNK_REMOVE = 0x00000800, // The section will not become part of the image. This is valid only for object files.
	IMAGE_SCN_LNK_COMDAT = 0x00001000, // The section contains COMDAT data. For more information, see section 5.5.6, “COMDAT Sections (Object Only).” This is valid only for object files.
	IMAGE_SCN_GPREL = 0x00008000, // The section contains data referenced through the global pointer (GP).
	IMAGE_SCN_MEM_PURGEABLE = 0x00020000, // Reserved for future use.
	IMAGE_SCN_MEM_16BIT = 0x00020000, // Reserved for future use.
	IMAGE_SCN_MEM_LOCKED = 0x00040000, // Reserved for future use.
	IMAGE_SCN_MEM_PRELOAD = 0x00080000, // Reserved for future use.
	IMAGE_SCN_ALIGN_1BYTES = 0x00100000, // Align data on a 1-byte boundary. Valid only for object files.
	IMAGE_SCN_ALIGN_2BYTES = 0x00200000, // Align data on a 2-byte boundary. Valid only for object files.
	IMAGE_SCN_ALIGN_4BYTES = 0x00300000, // Align data on a 4-byte boundary. Valid only for object files.
	IMAGE_SCN_ALIGN_8BYTES = 0x00400000, // Align data on an 8-byte boundary. Valid only for object files.
	IMAGE_SCN_ALIGN_16BYTES = 0x00500000, // Align data on a 16-byte boundary. Valid only for object files.
	IMAGE_SCN_ALIGN_32BYTES = 0x00600000, // Align data on a 32-byte boundary. Valid only for object files.
	IMAGE_SCN_ALIGN_64BYTES = 0x00700000, // Align data on a 64-byte boundary. Valid only for object files.
	IMAGE_SCN_ALIGN_128BYTES = 0x00800000, // Align data on a 128-byte boundary. Valid only for object files.
	IMAGE_SCN_ALIGN_256BYTES = 0x00900000, // Align data on a 256-byte boundary. Valid only for object files.
	IMAGE_SCN_ALIGN_512BYTES = 0x00A00000, // Align data on a 512-byte boundary. Valid only for object files.
	IMAGE_SCN_ALIGN_1024BYTES = 0x00B00000, // Align data on a 1024-byte boundary. Valid only for object files.
	IMAGE_SCN_ALIGN_2048BYTES = 0x00C00000, // Align data on a 2048-byte boundary. Valid only for object files.
	IMAGE_SCN_ALIGN_4096BYTES = 0x00D00000, // Align data on a 4096-byte boundary. Valid only for object files.
	IMAGE_SCN_ALIGN_8192BYTES = 0x00E00000, // Align data on an 8192-byte boundary. Valid only for object files.
	IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000, // The section contains extended relocations.
	IMAGE_SCN_MEM_DISCARDABLE = 0x02000000, // The section can be discarded as needed.
	IMAGE_SCN_MEM_NOT_CACHED = 0x04000000, // The section cannot be cached.
	IMAGE_SCN_MEM_NOT_PAGED = 0x08000000, // The section is not pageable.
	IMAGE_SCN_MEM_SHARED = 0x10000000, // The section can be shared in memory.
	IMAGE_SCN_MEM_EXECUTE = 0x20000000, // The section can be executed as code.
	IMAGE_SCN_MEM_READ = 0x40000000, // The section can be read.
	IMAGE_SCN_MEM_WRITE = 0x80000000, // The section can be written to.
};

coff_section_characteristics CoffAlignmentCharactersitics[] =
{
	IMAGE_SCN_ALIGN_1BYTES,
	IMAGE_SCN_ALIGN_2BYTES, 
	IMAGE_SCN_ALIGN_4BYTES,
	IMAGE_SCN_ALIGN_8BYTES,
	IMAGE_SCN_ALIGN_16BYTES,
	IMAGE_SCN_ALIGN_32BYTES,
	IMAGE_SCN_ALIGN_64BYTES,
	IMAGE_SCN_ALIGN_128BYTES,
	IMAGE_SCN_ALIGN_256BYTES,
	IMAGE_SCN_ALIGN_512BYTES,
	IMAGE_SCN_ALIGN_1024BYTES,
	IMAGE_SCN_ALIGN_2048BYTES,
	IMAGE_SCN_ALIGN_4096BYTES,
	IMAGE_SCN_ALIGN_8192BYTES,
};

enum obj_section_flags
{
	SectionExecute = 1 << 0,
	SectionRead = 1 << 1,
	SectionWrite = 1 << 2,

	SectionHasCode = 1 << 3,
	SectionHasData = 1 << 4,
	SectionHasZeroes = 1 << 5,

	SectionNoLink = 1 << 6,
};

struct obj_section
{
	const char *Name;

	uint32_t VirtualAlignment;
	uint32_t VirtualAddress;
	uint32_t VirtualSize;

	void *Data;
	uint32_t DataSize;

	uint32_t Flags;
};

struct obj_file
{
	obj_section *Sections;
	uint32_t NumSections;
};

const char *AllocStrLen(const char *s, uint32_t len)
{
	char *ptr = malloc(len + 1);
	memcpy(ptr, s, len);
	ptr[len] = '\0';
	return ptr;
}

TestCase(ExperimentLinkWin32)
{
	obj_file simpleObj = { 0 };

	{
		obj_file *obj = &simpleObj;

		char *fileData;
		size_t fileSize;

		TestReadFullFileFromData("simple_print.obj", (void**)&fileDataVoid, &fileSize);

		coff_file_header *fileHeader = (coff_file_header*)(fileData + 0);

		uint32_t nsec = fileHeader->NumberOfSections;
		coff_section_header *sectionHeaders = (coff_section_header*)(fileData + sizeof(coff_file_header));

		char *strtab = (char*)(fileData + sizeof(coff_file_header) + nsec * sizeof(coff_section_header));

		obj->Sections = calloc(sizeof(obj_section), nsec);
		obj->NumSections = nsec;

		for (uint32_t i = 0; i < nsec; i++)
		{
			obj_section *sec = obj->Sections[i]:
			coff_section_header *sh = &sectionHeaders[i];

			if (sh->Name[0] == '/')
			{
				uint32_t index = 0;
				for (uint32_t i = 1; i < 8; i++)
				{
					char c = sh->Name[i];
					if (c <= '0' || c >+ '9')
						break
					index = index * 10 + (c - '0');
				}
				sec->Name = strtab + index;
			}
			else
			{
				uint32_t len;
				for (len = 0; len < 8; len++)
				{
					if (sh->Name[len] == '\0')
						break;
				}
				sec->Name = AllocStrLen(sh->Name, len);
				sec->VirtualAddress = sh->VirtualAddress;
				sec->VirtualSize = sh->VirtualSize;
				uint32_t dataSize = sec->SizeOfRawData;
				sec->DataSize = dataSize;
				if (dataSize > 0)
				{
					sec->Data = malloc(dataSize);
					memcpy(sec->Data, fileData + sh->PointerToRawData, dataSize);
				}
			}

			uint32_t coffFlags = sh->Characteristics;
			for (uint32_t i = 0; i < ArrayCount(CoffAlignmentCharactersitics); i++)
			{
				if (coffFlags & CoffAlignmentCharactersitics[i])
				{
					sec->VirtualAlignment = 1 << i;
					break;
				}
			}

			uint32_t flags = 0;
			if (coffFlags & IMAGE_SCN_CNT_CODE)
				flags |= SectionHasCode;
			if (coffFlags & IMAGE_SCN_CNT_INITIALIZED_DATA)
				flags |= SectionHasData;
			if (coffFlags & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
				flags |= SectionHasZeroes;
			if (coffFlag & IMAGE_SCN_LNK_REMOVE)
				flags |= SectionNoLink;
			if (coffFlag & IMAGE_SCN_MEM_EXECUTE)
				flags |= SectionNoLink;
			if (coffFlag & IMAGE_SCN_MEM_READ)
				flags |= SectionNoLink;
			if (coffFlag & IMAGE_SCN_MEM_WRITE)
				flags |= SectionNoLink;

			uint32_t numReloc;
			if (coffFlag & IMAGE_SCN_LNK_NRELOC_OVFL)
			{
				numReloc = sh->VirtualSize;
				sec->VirtualSize = 0;
			}
			else
			{
				numReloc = sh->NumberOfRelocations;
			}

		}

		free(fileDataVoid);
	}
}

