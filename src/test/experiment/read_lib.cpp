#include "prelude.h"
#include "test/experiment/coff_defs.h"
#include "test/test_support.h"
#include "base/math/bit_math.h"
#include <string.h>
#include <time.h>

enum coff_section_characteristics
{
	IMAGE_SCN_TYPE_NO_PAD = 0x00000008, // The section should not be padded to the next boundary. This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES. This is valid only for object files.
	IMAGE_SCN_CNT_CODE = 0x00000020, // The section contains executable code.
	IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040, // The section contains initialized data.
	IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080, //The section contains uninitialized data.
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

enum
{
	IMAGE_SYM_CLASS_END_OF_FUNCTION = 0xFF, // A special symbol that represents the end of function, for debugging purposes.
	IMAGE_SYM_CLASS_NULL = 0, // No assigned storage class.
	IMAGE_SYM_CLASS_AUTOMATIC = 1, // The automatic (stack) variable. The Value field specifies the stack frame offset.
	IMAGE_SYM_CLASS_EXTERNAL = 2, // A value that Microsoft tools use for external symbols. The Value field indicates the size if the section number is IMAGE_SYM_UNDEFINED (0). If the section number is not zero, then the Value field specifies the offset within the section.
	IMAGE_SYM_CLASS_STATIC = 3, // The offset of the symbol within the section. If the Value field is zero, then the symbol represents a section name.
	IMAGE_SYM_CLASS_REGISTER = 4, // A register variable. The Value field specifies the register number.
	IMAGE_SYM_CLASS_EXTERNAL_DEF = 5, // A symbol that is defined externally.
	IMAGE_SYM_CLASS_LABEL = 6, // A code label that is defined within the module. The Value field specifies the offset of the symbol within the section.
	IMAGE_SYM_CLASS_UNDEFINED_LABEL = 7, // A reference to a code label that is not defined.
	IMAGE_SYM_CLASS_MEMBER_OF_STRUCT = 8, // The structure member. The Value field specifies the nth member.
	IMAGE_SYM_CLASS_ARGUMENT = 9, // A formal argument (parameter) of a function. The Value field specifies the nth argument.
	IMAGE_SYM_CLASS_STRUCT_TAG = 10, // The structure tag-name entry.
	IMAGE_SYM_CLASS_MEMBER_OF_UNION = 11, // A union member. The Value field specifies the nth member.
	IMAGE_SYM_CLASS_UNION_TAG = 12, // The Union tag-name entry.
	IMAGE_SYM_CLASS_TYPE_DEFINITION = 13, // A Typedef entry.
	IMAGE_SYM_CLASS_UNDEFINED_STATIC = 14, // A static data declaration.
	IMAGE_SYM_CLASS_ENUM_TAG = 15, // An enumerated type tagname entry.
	IMAGE_SYM_CLASS_MEMBER_OF_ENUM = 16, // A member of an enumeration. The Value field specifies the nth member.
	IMAGE_SYM_CLASS_REGISTER_PARAM = 17, // A register parameter.
	IMAGE_SYM_CLASS_BIT_FIELD = 18, // A bit-field reference. The Value field specifies the nth bit in the bit field.
	IMAGE_SYM_CLASS_BLOCK = 100, // A .bb (beginning of block) or .eb (end of block) record. The Value field is the relocatable address of the code location.
	IMAGE_SYM_CLASS_FUNCTION = 101, // A value that Microsoft tools use for symbol records that define the extent of a function: begin function (.bf), end function (.ef), and lines in function (.lf). For .lf records, the Value field gives the number of source lines in the function. For .ef records, the Value field gives the size of the function code.
	IMAGE_SYM_CLASS_END_OF_STRUCT = 102, // An end-of-structure entry.
	IMAGE_SYM_CLASS_FILE = 103, // A value that Microsoft tools, as well as traditional COFF format, use for the source-file symbol record. The symbol is followed by auxiliary records that name the file.
	IMAGE_SYM_CLASS_SECTION = 104, // A definition of a section (Microsoft tools use STATIC storage class instead).
	IMAGE_SYM_CLASS_WEAK_EXTERNAL = 105, // A weak external. For more information, see section 5.5.3, “Auxiliary Format 3: Weak Externals.”
	IMAGE_SYM_CLASS_CLR_TOKEN = 107, // A CLR token symbol. The name is an ASCII string that consists of the hexadecimal value of the token. For more information, see section 5.5.7, “CLR Token Definition (Object Only).”
};

enum
{
	IMPORT_ORDINAL = 0, // The import is by ordinal. This indicates that the value in the Ordinal/Hint field of the import header is the import’s ordinal. If this constant is not specified, then the Ordinal/Hint field should always be interpreted as the import’s hint.
	IMPORT_NAME = 1, // The import name is identical to the public symbol name.
	IMPORT_NAME_NOPREFIX = 2, // The import name is the public symbol name, but skipping the leading ?, @, or optionally _.
	IMPORT_NAME_UNDECORATE = 3, // The import name is the public symbol name, but skipping the leading ?, @, or optionally _, and truncating at the first @.
};

enum
{
	IMAGE_REL_AMD64_ABSOLUTE = 0x0000, // The relocation is ignored.
	IMAGE_REL_AMD64_ADDR64 = 0x0001, // The 64-bit VA of the relocation target.
	IMAGE_REL_AMD64_ADDR32 = 0x0002, // The 32-bit VA of the relocation target.
	IMAGE_REL_AMD64_ADDR32NB = 0x0003, // The 32-bit address without an image base (RVA).
	IMAGE_REL_AMD64_REL32 = 0x0004, // The 32-bit relative address from the byte following the relocation.
	IMAGE_REL_AMD64_REL32_1 = 0x0005, // The 32-bit address relative to byte distance 1 from the relocation.
	IMAGE_REL_AMD64_REL32_2 = 0x0006, // The 32-bit address relative to byte distance 2 from the relocation.
	IMAGE_REL_AMD64_REL32_3 = 0x0007, // The 32-bit address relative to byte distance 3 from the relocation.
	IMAGE_REL_AMD64_REL32_4 = 0x0008, // The 32-bit address relative to byte distance 4 from the relocation.
	IMAGE_REL_AMD64_REL32_5 = 0x0009, // The 32-bit address relative to byte distance 5 from the relocation.
	IMAGE_REL_AMD64_SECTION = 0x000A, // The 16-bit section index of the section that contains the target. This is used to support debugging information.
	IMAGE_REL_AMD64_SECREL = 0x000B, // The 32-bit offset of the target from the beginning of its section. This is used to support debugging information and static thread local storage.
	IMAGE_REL_AMD64_SECREL7 = 0x000C, // A 7-bit unsigned offset from the base of the section that contains the target.
	IMAGE_REL_AMD64_TOKEN = 0x000D, // CLR tokens.
	IMAGE_REL_AMD64_SREL32 = 0x000E, // A 32-bit signed span-dependent value emitted into the object.
	IMAGE_REL_AMD64_PAIR = 0x000F, // A pair that must immediately follow every span-dependent value.
	IMAGE_REL_AMD64_SSPAN32 = 0x0010, // A 32-bit signed span-dependent value that is applied at link time.
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

struct obj_relocation
{
	uint32_t Address;
	uint32_t SymbolIndex;
	uint32_t Type;
};

struct obj_section
{
	const char *Name;

	uint32_t VirtualAlignment;
	uint32_t VirtualAddress;
	uint32_t VirtualSize;

	void *Data;
	uint32_t DataSize;

	obj_relocation *Relocations;
	uint32_t NumRelocations;

	uint32_t Flags;
};

enum obj_symbol_type
{
	ObjSymbolDefine = 1 << 0,
	ObjSymbolInternal = 1 << 1,
	ObjSymbolExternal = 1 << 2,
};

struct obj_symbol
{
	const char *Name;
	uint32_t Address;
	uint32_t DefinedInSection;
	uint32_t Flags;
};

struct obj_dll_import
{
	const char *DllName;
	const char *ImportName;
	const char *SymbolName;
	uint32_t Hint;
};

enum obj_file_type
{
	ObjFileObject,
	ObjFileExecutable,
	ObjFileImport,
};

enum obj_file_pointer_type
{
	ObjFilePointerToEntryPoint,
	ObjFilePointerToImportDescriptorBegin,
	ObjFilePointerToImportAddressesBegin,
	ObjFilePointerToImportDescriptorEnd,
	ObjFilePointerToImportAddressesEnd,
	ObjFilePointerCount,
};

const char *objFilePointerSymbol[] =
{
	NULL,
	"___obj_idata_idt_begin",
	"___obj_idata_iat_begin",
	"___obj_idata_idt_end",
	"___obj_idata_iat_end",
};

struct obj_file_pointer
{
	uint32_t VirtualAddress;
};

struct obj_file
{
	const char *Name;
	obj_file_type FileType;

	uint32_t ImageBase;

	obj_section *Sections;
	uint32_t NumSections;

	obj_symbol *Symbols;
	uint32_t NumSymbols;

	obj_dll_import *DllImports;
	uint32_t NumDllImports;

	obj_file_pointer *FilePointers;
};

struct obj_archive_symbol
{
	const char *Name;
	uint32_t MemberIndex;
};

struct obj_archive_member
{
	const char *Name;
	obj_file ObjectFile;
};

struct obj_archive
{
	obj_archive_member *Members;
	uint32_t NumMembers;

	obj_archive_symbol *Symbols;
	uint32_t NumSymbols;
};

struct coff_archive_header
{
	uint8_t Name[16];
	uint8_t Date[12];
	uint8_t UserID[6];
	uint8_t GroupID[6];
	uint8_t Mode[8];
	uint8_t Size[10];
	uint8_t EndOfHeader[2];
};

char *AllocStrLen(const char *s, uint32_t len)
{
	char *ptr = (char*)malloc(len + 1);
	memcpy(ptr, s, len);
	ptr[len] = '\0';
	return ptr;
}

char *AllocStrZero(const char *s)
{
	uint32_t len = (uint32_t)strlen(s);
	return AllocStrLen(s, len);
}

void ReadCoffObject(obj_file *obj, const char *fileData, size_t fileSize)
{
	const coff_file_header *fileHeader = (const coff_file_header*)(fileData + 0);

	if (fileHeader->Machine == 0x0000 && fileHeader->NumberOfSections == 0xFFFF)
	{
		const coff_import_header *importHeader = (const coff_import_header*)fileHeader;
		obj->DllImports = (obj_dll_import*)calloc(sizeof(obj_dll_import), 1);
		obj->NumDllImports = 1;
		obj->FileType = ObjFileImport;

		obj_dll_import *imp = &obj->DllImports[0];

		const char *ptr = fileData + sizeof(coff_import_header);

		const char *symName = ptr;
		size_t symNameLen = strlen(ptr);
		ptr += symNameLen + 1;
		const char *dllName = ptr;
		size_t dllNameLen = strlen(ptr);
		ptr += dllNameLen + 1;

		uint16_t type = importHeader->Type;
		uint32_t nameType = (type >> 2) & 0x7;

		imp->DllName = AllocStrLen(dllName, dllNameLen);
		imp->SymbolName = AllocStrLen(symName, symNameLen);
		imp->Hint = importHeader->OrdinalOrHint;

		switch (nameType)
		{
		case IMPORT_ORDINAL:
			imp->ImportName = 0;
			break;
		case IMPORT_NAME:
			imp->ImportName = AllocStrZero(imp->SymbolName);
			break;
		case IMPORT_NAME_UNDECORATE:
		case IMPORT_NAME_NOPREFIX:
			{
				const char *begin = symName;
				char c = begin[0];
				if (c == '?' || c == '@' || c == '_')
					begin++;

				const char *end = symName + symNameLen;
				if (nameType == IMPORT_NAME_UNDECORATE)
				{
					for (end = begin; *end; end++)
					{
						if (*end == '@')
							break;
					}
				}

				imp->ImportName = AllocStrLen(begin, (uint32_t)(end - begin));
			}
		}

		return;
	}

	obj->FileType = ObjFileObject;

	uint32_t nsec = fileHeader->NumberOfSections;
	const coff_section_header *sectionHeaders = (const coff_section_header*)(fileData + sizeof(coff_file_header));

	uint32_t nsym = fileHeader->NumberOfSymbols;
	const coff_symbol *symbolTable = (const coff_symbol*)(fileData + fileHeader->PointerToSymbolTable);

	char *strtab = (char*)symbolTable + nsym * sizeof(coff_symbol);

	obj->Sections = (obj_section*)calloc(sizeof(obj_section), nsec);
	obj->NumSections = nsec;

	obj->Symbols = (obj_symbol*)calloc(sizeof(obj_symbol), nsym);

	for (uint32_t i = 0; i < nsym; i++)
	{
		obj_symbol *osy = &obj->Symbols[i];
		const coff_symbol *csy = &symbolTable[i];

		if (csy->Name.Long.Zeroes == 0)
		{
			osy->Name = AllocStrZero(strtab + csy->Name.Long.StringIndex);
		}
		else
		{
			const char *name = (const char*)csy->Name.Short;
			uint32_t len;
			for (len = 0; len < 8; len++)
			{
				if (name[len] == '\0')
					break;
			}
			osy->Name = AllocStrLen(name, len);
		}

		for (int j = 0; j < csy->NumberOfAuxSymbols; j++)
		{
			i++;

			obj_symbol *aux = &obj->Symbols[i];
			aux->Name = "";
			aux->Address = 0;
			aux->DefinedInSection = 0;
			aux->Flags = 0;
		}

		uint32_t flags = 0;
		int32_t sec = (int16_t)csy->SectionNumber;
		if (sec > 0)
		{
			osy->DefinedInSection = sec - 1;
			osy->Address = csy->Value;
			flags |= ObjSymbolDefine;
		}
		else
		{
			osy->DefinedInSection = 0;
			osy->Address = 0;
		}

		if (csy->StorageClass == IMAGE_SYM_CLASS_STATIC)
			flags |= ObjSymbolInternal;
		if (csy->StorageClass == IMAGE_SYM_CLASS_EXTERNAL)
			flags |= ObjSymbolExternal;

		osy->Flags = flags;
	}
	obj->NumSymbols = nsym;

	for (uint32_t secI = 0; secI < nsec; secI++)
	{
		obj_section *sec = &obj->Sections[secI];
		const coff_section_header *sh = &sectionHeaders[secI];

		if (sh->Name[0] == '/')
		{
			uint32_t index = 0;
			for (uint32_t i = 1; i < 8; i++)
			{
				char c = sh->Name[i];
				if (c <= '0' || c >+ '9')
					break;
				index = index * 10 + (c - '0');
			}
			sec->Name = AllocStrZero(strtab + index);
		}
		else
		{
			uint32_t len;
			for (len = 0; len < 8; len++)
			{
				if (sh->Name[len] == '\0')
					break;
			}
			sec->Name = AllocStrLen((const char*)sh->Name, len);
		}

		sec->VirtualAddress = sh->VirtualAddress;
		sec->VirtualSize = sh->Misc.VirtualSize;
		uint32_t dataSize = sh->SizeOfRawData;
		sec->DataSize = dataSize;
		sec->VirtualSize = dataSize;
		if (dataSize > 0)
		{
			sec->Data = malloc(dataSize);
			memcpy(sec->Data, fileData + sh->PointerToRawData, dataSize);
		}

		sec->VirtualAlignment = 0;
		uint32_t coffFlags = sh->Characteristics;
		uint32_t alignment = (coffFlags >> 5*4) & 0xF;
		sec->VirtualAlignment = 1 << (alignment - 1);

		uint32_t flags = 0;
		if (coffFlags & IMAGE_SCN_CNT_CODE)
			flags |= SectionHasCode;
		if (coffFlags & IMAGE_SCN_CNT_INITIALIZED_DATA)
			flags |= SectionHasData;
		if (coffFlags & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
			flags |= SectionHasZeroes;
		if (coffFlags & IMAGE_SCN_LNK_REMOVE)
			flags |= SectionNoLink;
		if (coffFlags & IMAGE_SCN_MEM_EXECUTE)
			flags |= SectionExecute;
		if (coffFlags & IMAGE_SCN_MEM_READ)
			flags |= SectionRead;
		if (coffFlags & IMAGE_SCN_MEM_WRITE)
			flags |= SectionWrite;
		sec->Flags = flags;

		uint32_t numReloc;
		if (coffFlags & IMAGE_SCN_LNK_NRELOC_OVFL)
		{
			numReloc = sh->VirtualAddress;
			sec->VirtualAddress = 0;
		}
		else
		{
			numReloc = sh->NumberOfRelocations;
		}

		sec->NumRelocations = numReloc;
		if (numReloc > 0)
		{
			const coff_relocation *cr = (coff_relocation*)(fileData + sh->PointerToRelocations);
			sec->Relocations = (obj_relocation*)malloc(sizeof(obj_relocation) * numReloc);
			for (uint32_t i = 0; i < numReloc; i++)
			{
				obj_relocation *obr = &sec->Relocations[i];
				obr->Address = cr[i].VirtualAddress;
				obr->SymbolIndex = cr[i].SymbolTableIndex;
				obr->Type = cr[i].Type;
			}
		}
		else
		{
			sec->Relocations = 0;
		}
	}
}

void ReadCoffArchive(obj_archive *arc, const char *fileData, size_t fileSize)
{
	const char *header = fileData;
	if (memcmp(header, "!<arch>\n", 8) != 0)
		return;

	uint32_t filePos = 8;

	obj_archive_member *arcMem = 0;
	uint32_t arcCapacity = 0;
	uint32_t arcCount = 0;

	const char *longNames = 0;

	uint32_t linkerMemberIndex = 0;

	while (filePos < fileSize)
	{
		const coff_archive_header *header = (const coff_archive_header*)(fileData + filePos);
		filePos += sizeof(coff_archive_header);
		uint32_t memSize = 0;
		for (uint32_t i = 0; i < 10; i++)
		{
			char c = header->Size[i];
			if (c < '0' || c > '9')
				break;
			memSize = memSize * 10 + (c - '0');
		}

		const char *memData = fileData + filePos;
		const char *memName = 0;

		if (header->Name[0] == '/')
		{
			if (header->Name[1] == ' ')
			{
				if (linkerMemberIndex == 0)
				{
				}
				else if (linkerMemberIndex == 1)
				{
					const char *memPtr = memData;
					uint32_t numMembers = *(uint32_unalgined_le*)memPtr;
					memPtr += 4;
					memPtr += 4 * numMembers;

					if (arcMem == 0)
					{
						arcMem = (obj_archive_member*)calloc(sizeof(obj_archive_member), numMembers);
						arcCapacity = numMembers;
					}

					uint32_t numSym = *(uint32_unalgined_le*)memPtr;
					memPtr += 4;

					uint16_unalgined_le *indexPtr = (uint16_unalgined_le*)memPtr;
					const char *strPtr = memPtr + 2 * numSym;

					arc->Symbols = (obj_archive_symbol*)malloc(sizeof(obj_archive_symbol) * numSym);
					arc->NumSymbols = numSym;

					for (uint32_t i = 0; i < numSym; i++)
					{
						uint32_t len = (uint32_t)strlen(strPtr);
						arc->Symbols[i].Name = AllocStrLen(strPtr, len);
						strPtr += len + 1;

						arc->Symbols[i].MemberIndex = indexPtr[i] - 1;
					}
				}
				else
				{
				}

				linkerMemberIndex++;
			}
			else if (header->Name[1] == '/')
			{
				longNames = memData;
			}
			else
			{
				uint32_t num = 0;
				for (uint32_t i = 1; i < 16; i++)
				{
					char c = header->Name[i];
					if (c < '0' || c > '9')
						break;
					num = num * 10 + (c - '0');
				}
				memName = AllocStrZero(longNames + num);
			}
		}
		else
		{
			uint32_t len;
			for (len = 1; len < 16; len++)
			{
				if (header->Name[len] == '/')
					break;
			}
			memName = AllocStrLen((char*)header->Name, len);
		}

		if (memName)
		{
			if (arcCount >= arcCapacity)
			{
				arcCapacity = arcCapacity ? arcCapacity * 2 : 4;
				arcMem = (obj_archive_member*)realloc(arcMem, sizeof(obj_archive_member) * arcCapacity);
				memset(arcMem, 0, (arcCapacity - arcCount) * sizeof(obj_archive_member));
			}

			obj_archive_member *mem = &arcMem[arcCount];
			mem->Name = memName;
			ReadCoffObject(&mem->ObjectFile, memData, memSize);
			mem->ObjectFile.Name = AllocStrZero(memName);

			arcCount++;
		}

		filePos += memSize;
		filePos = AlignValue(filePos, 2);
	}

	arc->Members = arcMem;
	arc->NumMembers = arcCount;
}

struct link_input
{
	const obj_file **Objects;
	uint32_t NumObjects;

	const obj_archive **Archives;
	uint32_t NumArchives;

	uint32_t ImageBase;
	const char *EntryPointName;
};

struct link_output
{
	obj_file *Object;
};

struct link_symbol
{
	uint32_t VirtualAddress;
	uint32_t ExternIndex;
};

struct link_obj;

struct link_section
{
	link_obj *Obj;
	const obj_section *ObjSection;
	uint32_t OffsetInSection;
	uint32_t VirtualAddress;
};

struct link_obj
{
	const obj_file *ObjFile;
	link_section *Sections;
	link_symbol *Symbols;
};

struct link_extern
{
	const char *Name;
	uint32_t VirtualAddress;
	link_obj *DefiningObj;
};

struct link_dll
{
	const char *Name;
	const obj_dll_import **Imports;
	uint32_t Count;
	uint32_t Capacity;
};

struct link_final_section
{
	char *Name;

	link_section **Sections;

	uint32_t NumSections;
	uint32_t VirtualAlignment;
	uint32_t TotalDataSize;
	uint32_t Flags;

	uint32_t VirtualAddress;
};

void CreateDllObject(obj_file *obj, const obj_dll_import *imports, uint32_t numImports)
{
	link_dll *dlls = (link_dll*)calloc(sizeof(link_dll), 1024);
	uint32_t numDlls = 0;
	obj->FileType = ObjFileObject;

	for (uint32_t impI = 0; impI < numImports; impI++)
	{
		const obj_dll_import *imp = &imports[impI];

		link_dll *dll = NULL;
		for (uint32_t i = 0; i < numDlls; i++)
		{
			if (!strcmp(dlls[i].Name, imp->DllName))
			{
				dll = &dlls[i];
				break;
			}
		}

		if (dll == NULL)
		{
			dll = &dlls[numDlls];
			dll->Name = imp->DllName;
			numDlls++;
		}

		if (dll->Count >= dll->Capacity)
		{
			dll->Capacity = dll->Capacity ? 2 * dll->Capacity : 4;
			dll->Imports = (const obj_dll_import**)realloc(dll->Imports, sizeof(obj_dll_import*) * dll->Capacity);
		}
		dll->Imports[dll->Count] = imp;
		dll->Count++;
	}

	obj->NumSections = 6;
	obj->Sections = (obj_section*)calloc(sizeof(obj_section), obj->NumSections);

	obj->Symbols = (obj_symbol*)calloc(sizeof(obj_symbol), 1024);
	uint32_t numSym = 0;

	{
		obj_section *secIdt = &obj->Sections[0];
		secIdt->Name = AllocStrZero(".idata$1_idt");
		secIdt->NumRelocations = 3 * numDlls;
		secIdt->Relocations = (obj_relocation*)calloc(sizeof(obj_relocation), secIdt->NumRelocations);
		secIdt->Data = calloc(1024,1024);
		secIdt->Flags = SectionRead|SectionWrite|SectionHasData;

		obj_section *secIlt = &obj->Sections[1];
		secIlt->Name = AllocStrZero(".idata$2_ilt");
		secIlt->Relocations = (obj_relocation*)calloc(sizeof(obj_relocation), secIdt->NumRelocations);
		secIlt->Data = calloc(1024,1024);
		secIlt->Flags = SectionRead|SectionWrite|SectionHasData;

		obj_section *secIat = &obj->Sections[2];
		secIat->Name = AllocStrZero(".idata$3_iat");
		secIat->Relocations = (obj_relocation*)calloc(sizeof(obj_relocation), secIdt->NumRelocations);
		secIat->Data = calloc(1024,1024);
		secIat->Flags = SectionRead|SectionWrite|SectionHasData;

		obj_section *secHnt = &obj->Sections[3];
		secHnt->Name = AllocStrZero(".idata$4_hnt");
		secHnt->Data = calloc(1024,1024);
		secHnt->Flags = SectionRead|SectionWrite|SectionHasData;

		obj_section *secStr = &obj->Sections[4];
		secStr->Name = AllocStrZero(".idata$5_str");
		secStr->Data = calloc(1024,1024);
		secStr->Flags = SectionRead|SectionWrite|SectionHasData;

		obj_section *secText = &obj->Sections[5];
		secText->Name = AllocStrZero(".text$dll");
		secText->Relocations = (obj_relocation*)calloc(sizeof(obj_relocation), secIdt->NumRelocations);
		secText->Data = calloc(1024,1024);
		secText->Flags = SectionRead|SectionExecute|SectionHasCode;

		*(uint8_t*)secText->Data = 0xCC;
		secText->DataSize = 1;

		char buf[128];

		uint32_t idtRelocNum = 0;
		uint32_t iltRelocNum = 0;

		for (uint32_t dllI = 0; dllI < numDlls; dllI++)
		{
			link_dll *dll = &dlls[dllI];

			uint32_t sb = numSym;

			sprintf(buf, "%s name", dll->Name);
			obj->Symbols[sb + 0].Name = AllocStrZero(buf);
			obj->Symbols[sb + 0].Address = secStr->DataSize;
			obj->Symbols[sb + 0].DefinedInSection = 4;
			obj->Symbols[sb + 0].Flags = ObjSymbolDefine|ObjSymbolInternal;

			sprintf(buf, "%s ilt", dll->Name);
			obj->Symbols[sb + 1].Name = AllocStrZero(buf);
			obj->Symbols[sb + 1].Address = secIlt->DataSize;
			obj->Symbols[sb + 1].DefinedInSection = 1;
			obj->Symbols[sb + 1].Flags = ObjSymbolDefine|ObjSymbolInternal;

			sprintf(buf, "%s iat", dll->Name);
			obj->Symbols[sb + 2].Name = AllocStrZero(buf);
			obj->Symbols[sb + 2].Address = secIlt->DataSize;
			obj->Symbols[sb + 2].DefinedInSection = 2;
			obj->Symbols[sb + 2].Flags = ObjSymbolDefine|ObjSymbolInternal;

			{
				obj_relocation *rl = secIdt->Relocations + idtRelocNum;
				rl[0].Address = secIdt->DataSize + 0;
				rl[0].SymbolIndex = sb + 1;
				rl[0].Type = IMAGE_REL_AMD64_ADDR32NB;
				rl[1].Address = secIdt->DataSize + 12;
				rl[1].SymbolIndex = sb + 0;
				rl[1].Type = IMAGE_REL_AMD64_ADDR32NB;
				rl[2].Address = secIdt->DataSize + 16;
				rl[2].SymbolIndex = sb + 2;
				rl[2].Type = IMAGE_REL_AMD64_ADDR32NB;
			}

			secIdt->DataSize += 20;

			idtRelocNum += 3;
			numSym += 3;

			uint32_t len = (uint32_t)strlen(dll->Name) + 1;
			memcpy((char*)secStr->Data + secStr->DataSize, dll->Name, len);
			secStr->DataSize += len;

			for (uint32_t impI = 0; impI < dll->Count; impI++)
			{
				const obj_dll_import *imp = dll->Imports[impI];

				if (imp->ImportName)
				{
					sprintf(buf, "%s %s hnt", dll->Name, imp->ImportName);
					obj->Symbols[numSym].Name = AllocStrZero(buf);
					obj->Symbols[numSym].Address = secHnt->DataSize;
					obj->Symbols[numSym].DefinedInSection = 3;
					obj->Symbols[numSym].Flags = ObjSymbolDefine|ObjSymbolInternal;

					obj_relocation *rl = secIlt->Relocations + iltRelocNum;
					rl->Address = secIlt->DataSize;
					rl->SymbolIndex = numSym;
					rl->Type = IMAGE_REL_AMD64_ADDR32NB;
					secIat->Relocations[iltRelocNum] = *rl;
					iltRelocNum++;

					uint32_t nameLen = (uint32_t)strlen(imp->ImportName) + 1;
					char *hnt = (char*)secHnt->Data + secHnt->DataSize;
					uint16_le *hint = (uint16_le*)hnt;
					*hint = imp->Hint;

					memcpy(hnt + 2, imp->ImportName, nameLen);

					secHnt->DataSize += 2 + nameLen;
					secHnt->DataSize = AlignValue(secHnt->DataSize, 2);
					numSym++;
				}
				else
				{
					uint64_le *ilt = (uint64_le*)((char*)secIlt->Data + secIlt->DataSize);
					*ilt = 1ULL << 63 | imp->Hint;
				}

				sprintf(buf, "__imp_%s", imp->ImportName);
				obj->Symbols[numSym].Name = AllocStrZero(buf);
				obj->Symbols[numSym].Address = secIlt->DataSize;
				obj->Symbols[numSym].DefinedInSection = 2;
				obj->Symbols[numSym].Flags = ObjSymbolDefine|ObjSymbolExternal;

				uint8_t *text = (uint8_t*)secText->Data + secText->DataSize;
				text[0] = 0xFF;
				text[1] = 0x25;

				{
					obj_relocation *rl = secText->Relocations + secText->NumRelocations;
					secText->NumRelocations++;

					rl->Address = secText->DataSize + 2;
					rl->SymbolIndex = numSym;
					rl->Type = IMAGE_REL_AMD64_REL32;

					obj->Symbols[numSym + 1].Name = AllocStrZero(imp->SymbolName);
					obj->Symbols[numSym + 1].Address = secText->DataSize;
					obj->Symbols[numSym + 1].DefinedInSection = 5;
					obj->Symbols[numSym + 1].Flags = ObjSymbolDefine|ObjSymbolExternal;
				}

				secText->DataSize += 6;

				numSym += 2;

				secIlt->DataSize += 8;
			}

			secIlt->DataSize += 8;
		}

		memcpy(secIat->Data, secIlt->Data, secIlt->DataSize);
		secIat->DataSize = secIlt->DataSize;

		obj->Symbols[numSym].Name = objFilePointerSymbol[ObjFilePointerToImportDescriptorBegin];
		obj->Symbols[numSym].Address = 0;
		obj->Symbols[numSym].DefinedInSection = 0;
		obj->Symbols[numSym].Flags = ObjSymbolDefine|ObjSymbolExternal;
		numSym++;

		obj->Symbols[numSym].Name = objFilePointerSymbol[ObjFilePointerToImportAddressesBegin];
		obj->Symbols[numSym].Address = 0;
		obj->Symbols[numSym].DefinedInSection = 2;
		obj->Symbols[numSym].Flags = ObjSymbolDefine|ObjSymbolExternal;
		numSym++;

		obj->Symbols[numSym].Name = objFilePointerSymbol[ObjFilePointerToImportDescriptorEnd];
		obj->Symbols[numSym].Address = secIdt->DataSize;
		obj->Symbols[numSym].DefinedInSection = 0;
		obj->Symbols[numSym].Flags = ObjSymbolDefine|ObjSymbolExternal;
		numSym++;

		obj->Symbols[numSym].Name = objFilePointerSymbol[ObjFilePointerToImportAddressesEnd];
		obj->Symbols[numSym].Address = secIat->DataSize;
		obj->Symbols[numSym].DefinedInSection = 2;
		obj->Symbols[numSym].Flags = ObjSymbolDefine|ObjSymbolExternal;
		numSym++;


		secIdt->DataSize += 20;
		secIlt->NumRelocations = iltRelocNum;
		secIat->NumRelocations = iltRelocNum;
		obj->NumSymbols = numSym;

		for (uint32_t secI = 0; secI < obj->NumSections; secI++)
		{
			obj->Sections[secI].VirtualSize = obj->Sections[secI].DataSize;
			obj->Sections[secI].VirtualAlignment = 16;
		}
	}
}

uint32_t WriteCoffObject(const obj_file *obj, void *dataVoid, size_t dataSize)
{
	char *data = (char*)dataVoid;
	char *pos = data;

	if (obj->FileType == ObjFileExecutable)
	{
		uint32_t peOffset = AlignValuePow2(sizeof(pe_dos_header) + 32, 8);
		pe_dos_header *dh = (pe_dos_header*)pos;
		dh->signature[0] = 'M';
		dh->signature[1] = 'Z';
		dh->e_lfanew = peOffset;

		pos += peOffset;

		memcpy(pos, "PE\0\0", 4);
		pos += 4;
	}

	coff_file_header *fh = (coff_file_header*)pos;
	pos += sizeof(coff_file_header);
	fh->Machine = 0x8664;
	fh->NumberOfSections = obj->NumSections;
	fh->TimeDateStamp = (uint32_t)time(NULL);
	fh->NumberOfSymbols = obj->NumSymbols;

	uint32_t fileAlignment = obj->FileType == ObjFileExecutable ? 512 : 1;

	if (obj->FileType == ObjFileExecutable)
	{
		fh->SizeOfOptionalHeader = 112 + 16 * 8;
		fh->Characteristics = 0x0001 | 0x0002 | 0x0020;

		uint32_t baseOfCode = ~0;
		uint32_t sizeOfCode = 0;
		uint32_t sizeOfInitializedData = 0;
		uint32_t sizeOfUnitializedData = 0;
		uint32_t imageSize = 0;

		for (uint32_t secI = 0; secI < obj->NumSections; secI++)
		{
			const obj_section *sec = &obj->Sections[secI];
			if (sec->Flags & SectionHasCode)
			{
				sizeOfCode += sec->VirtualSize;
				if (baseOfCode == ~0)
					baseOfCode = sec->VirtualAddress;
			}
			if (sec->Flags & SectionHasData)
				sizeOfInitializedData += sec->VirtualSize;
			if (sec->Flags & SectionHasZeroes)
				sizeOfUnitializedData += sec->VirtualSize;

			uint32_t top = sec->VirtualAddress + sec->VirtualSize;
			if (top > imageSize)
				imageSize = top;
		}

		{
			coff_optional_header0 *opt = (coff_optional_header0*)pos;
			pos += sizeof(coff_optional_header0);
			opt->Magic = 0x20b;
			opt->MajorLinkerVersion = 11;
			opt->MinorLinkerVersion = 0;
			opt->SizeOfCode = sizeOfCode;
			opt->SizeOfInitializedData = sizeOfInitializedData;
			opt->SizeOfUninitializedData = sizeOfUnitializedData;
			opt->AddressOfEntryPoint = obj->FilePointers[ObjFilePointerToEntryPoint].VirtualAddress;
			opt->BaseOfCode = baseOfCode;
		}

		{
			coff_optional_header1_64 *opt = (coff_optional_header1_64*)pos;
			pos += sizeof(coff_optional_header1_64);
			opt->ImageBase = obj->ImageBase;
		}

		{
			coff_optional_header2 *opt = (coff_optional_header2*)pos;
			pos += sizeof(coff_optional_header2);
			opt->SectionAlignment = 4096;
			opt->FileAlignment = fileAlignment;
			opt->MajorOperatingSystemVersion = 6;
			opt->MinorOperatingSystemVersion = 0;
			opt->MajorImageVersion = 0;
			opt->MinorImageVersion = 0;
			opt->MajorSubsystemVersion = 6;
			opt->MinorSubsystemVersion = 0;
			opt->Win32VersionValue = 0;
			opt->SizeOfImage = AlignValue(imageSize, opt->SectionAlignment);
			opt->SizeOfHeaders = 1024;
			opt->CheckSum = 0;
			opt->Subsystem = 2;
			opt->DllCharacteristics = 0;
		}

		{
			coff_optional_header3_64 *opt = (coff_optional_header3_64*)pos;
			pos += sizeof(coff_optional_header3_64);
			opt->SizeOfStackReserve = 1024;
			opt->SizeOfStackCommit = 1024;
			opt->SizeOfHeapReserve = 1024;
			opt->SizeOfHeapCommit = 1024;
		}

		{
			coff_optional_header4 *opt = (coff_optional_header4*)pos;
			pos += sizeof(coff_optional_header4);
			opt->LoaderFlags = 0;
			opt->NumberOfRvaAndSizes = 16;
		}

		coff_data_directory *dd = (coff_data_directory*)pos;
		dd[1].VirtualAddress = obj->FilePointers[ObjFilePointerToImportDescriptorBegin].VirtualAddress;
		dd[1].Size = obj->FilePointers[ObjFilePointerToImportDescriptorEnd].VirtualAddress - obj->FilePointers[ObjFilePointerToImportDescriptorBegin].VirtualAddress;
		dd[12].VirtualAddress = obj->FilePointers[ObjFilePointerToImportAddressesBegin].VirtualAddress;
		dd[12].Size = obj->FilePointers[ObjFilePointerToImportAddressesEnd].VirtualAddress - obj->FilePointers[ObjFilePointerToImportAddressesBegin].VirtualAddress;
		pos += sizeof(coff_data_directory) * 16;
	}
	else
	{
		fh->SizeOfOptionalHeader = 0;
		fh->Characteristics = 0;
	}

	coff_section_header *shs = (coff_section_header*)pos;
	pos += sizeof(coff_section_header) * obj->NumSections;

	uint32_t rawDataPos = pos - data;

	char *stringTable = (char*)malloc(1024*1024);
	uint32_t stringTablePos = 4;

	for (uint32_t secI = 0; secI < obj->NumSections; secI++)
	{
		obj_section *sec = &obj->Sections[secI];
		coff_section_header *sh = &shs[secI];
		uint32_t len = (uint32_t)strlen(sec->Name);

		if (len <= 8 || obj->FileType == ObjFileExecutable)
		{
			if (len > 8)
				len = 8;
			memcpy(sh->Name, sec->Name, len + 1);
		}
		else
		{
			sprintf((char*)sh->Name, "/%d", stringTablePos);
			memcpy(stringTable + stringTablePos, sec->Name, len + 1);
			stringTablePos += len + 1;
		}

		sh->Misc.VirtualSize = sec->VirtualSize;
		sh->VirtualAddress = sec->VirtualAddress;
		sh->SizeOfRawData = sec->DataSize;
		
		if (sec->DataSize > 0)
		{
			rawDataPos = AlignValue(rawDataPos, fileAlignment);
			sh->PointerToRawData = rawDataPos;
			memcpy((char*)data + rawDataPos, sec->Data, sec->DataSize);
			rawDataPos += sec->DataSize;
		}

		sh->NumberOfRelocations = sec->NumRelocations;
		if (sec->NumRelocations > 0)
		{
			rawDataPos = AlignValue(rawDataPos, 4);
			sh->PointerToRelocations = rawDataPos;
			coff_relocation *cr = (coff_relocation*)((char*)data + rawDataPos);
			for (uint32_t rI = 0; rI < sec->NumRelocations; rI++)
			{
				const obj_relocation *rl = &sec->Relocations[rI];
				cr[rI].VirtualAddress = rl->Address;
				cr[rI].SymbolTableIndex = rl->SymbolIndex;
				cr[rI].Type = rl->Type;
			}
			rawDataPos += sizeof(coff_relocation) * sec->NumRelocations;
		}

		uint32_t flags = 0;

		if (obj->FileType != ObjFileExecutable)
		{
			uint32_t alignmentField = 0;
			uint32_t alignmentLeft = sec->VirtualAlignment;
			while (alignmentLeft > 0)
			{
				alignmentLeft >>= 1;
				alignmentField++;
			}
			flags |= alignmentField << 5*4;
		}

		if (sec->Flags & SectionHasCode)
			flags |= IMAGE_SCN_CNT_CODE;
		if (sec->Flags & SectionHasData)
			flags |= IMAGE_SCN_CNT_INITIALIZED_DATA;
		if (sec->Flags & SectionHasZeroes)
			flags |= IMAGE_SCN_CNT_UNINITIALIZED_DATA;
		if (sec->Flags & SectionNoLink)
			flags |= IMAGE_SCN_LNK_REMOVE;
		if (sec->Flags & SectionExecute)
			flags |= IMAGE_SCN_MEM_EXECUTE;
		if (sec->Flags & SectionRead)
			flags |= IMAGE_SCN_MEM_READ;
		if (sec->Flags & SectionWrite)
			flags |= IMAGE_SCN_MEM_WRITE;

		sh->Characteristics = flags;
	}

	rawDataPos = AlignValue(rawDataPos, 16);
	fh->PointerToSymbolTable = rawDataPos;

	coff_symbol *css = (coff_symbol*)((char*)data + rawDataPos);

	for (uint32_t symI = 0; symI < obj->NumSymbols; symI++)
	{
		const obj_symbol *sym = &obj->Symbols[symI];
		coff_symbol *cs = &css[symI];

		uint32_t nameLen = (uint32_t)strlen(sym->Name);

		if (nameLen <= 8)
		{
			memcpy(cs->Name.Short, sym->Name, nameLen);
		}
		else
		{
			cs->Name.Long.Zeroes = 0;
			cs->Name.Long.StringIndex = stringTablePos;

			memcpy(stringTable + stringTablePos, sym->Name, nameLen + 1);
			stringTablePos += nameLen + 1;
		}

		cs->Value = sym->Address;
		if (sym->Flags & ObjSymbolDefine)
		{
			cs->SectionNumber = sym->DefinedInSection + 1;
		}
		else
		{
			cs->SectionNumber = 0;
		}

		if (sym->Flags & ObjSymbolInternal)
			cs->StorageClass = IMAGE_SYM_CLASS_STATIC;
		else if (sym->Flags & ObjSymbolExternal)
			cs->StorageClass = IMAGE_SYM_CLASS_EXTERNAL;

		cs->Type = 0;
		cs->NumberOfAuxSymbols = 0;
	}

	rawDataPos += obj->NumSymbols * sizeof(coff_symbol);

	*(uint32_le*)stringTable = stringTablePos;
	memcpy((char*)data + rawDataPos, stringTable, stringTablePos);
	rawDataPos += stringTablePos;

	data += rawDataPos;
	return data - (char*)dataVoid;
}

int CompareSectionsInFinalSection(const void *a, const void *b)
{
	const link_section *as = *(const link_section**)a;
	const link_section *bs = *(const link_section**)b;
	return strcmp(as->ObjSection->Name, bs->ObjSection->Name);
}

void Link(link_output *output, const link_input *input)
{
	link_extern *externs = (link_extern*)calloc(sizeof(link_extern), 1024);
	link_obj *linkObjects = (link_obj*)calloc(sizeof(link_obj), 1024);
	uint32_t numExterns = 0;
	uint32_t numLinkObjects = 0;

	obj_file genDllObjFile = { 0 };
	obj_dll_import *genDllImports = (obj_dll_import*)calloc(sizeof(obj_dll_import), 1024);
	uint32_t numDllImports = 0;

	genDllObjFile.Name = "(generated dll object)";

	const obj_file **objToProcess = (const obj_file**)calloc(sizeof(obj_file*), 1024);
	uint32_t numObjToProcess = 0;

	for (uint32_t i = 0; i < input->NumObjects; i++)
	{
		objToProcess[numObjToProcess] = input->Objects[i];
		numObjToProcess++;
	}

	bool generatedDll = false;

	while (numObjToProcess > 0)
	{
		for (uint32_t objI = 0; objI < numObjToProcess; objI++)
		{
			const obj_file *obj = objToProcess[objI];
			link_obj *lobj = &linkObjects[numLinkObjects];
			lobj->ObjFile = obj;
			lobj->Symbols = (link_symbol*)calloc(sizeof(link_symbol), obj->NumSymbols);
			lobj->Sections = (link_section*)calloc(sizeof(link_section), obj->NumSections);
			numLinkObjects++;

			for (uint32_t secI = 0; secI < obj->NumSections; secI++)
			{
				lobj->Sections[secI].Obj = lobj;
				lobj->Sections[secI].ObjSection = &obj->Sections[secI];
			}

			for (uint32_t symI = 0; symI < obj->NumSymbols; symI++)
			{
				const obj_symbol *os = &obj->Symbols[symI];
				link_symbol *ls = &lobj->Symbols[symI];

				if (os->Flags & ObjSymbolExternal)
				{
					link_extern *ext = NULL;
					for (uint32_t exI = 0; exI < numExterns; exI++)
					{
						if (!strcmp(externs[exI].Name, os->Name))
							ext = externs + exI;
					}
					if (!ext)
					{
						ext = &externs[numExterns++];
						ext->Name = os->Name;
					}

					if (os->Flags & ObjSymbolDefine)
					{
						Assert(ext->DefiningObj == NULL || ext->DefiningObj->ObjFile->FileType == ObjFileImport);
						ext->DefiningObj = lobj;
					}

					ls->ExternIndex = ext - externs;
				}
				else
				{
					ls->ExternIndex = ~0;
				}
			}

			for (uint32_t dynI = 0; dynI < obj->NumDllImports; dynI++)
			{
				obj_dll_import *dyn = &obj->DllImports[dynI];
				link_extern *ext = NULL;
				for (uint32_t exI = 0; exI < numExterns; exI++)
				{
					if (!strcmp(externs[exI].Name, dyn->SymbolName))
						ext = externs + exI;
				}
				if (!ext)
				{
					ext = &externs[numExterns++];
					ext->Name = dyn->SymbolName;
				}

				genDllImports[numDllImports] = *dyn;
				numDllImports++;

				ext->DefiningObj = lobj;
			}
		}

		numObjToProcess = 0;

		for (uint32_t exI = 0; exI < numExterns; exI++)
		{
			link_extern *ext = &externs[exI];
			if (ext->DefiningObj != NULL)
				continue;

			for (uint32_t arcI = 0; arcI < input->NumArchives; arcI++)
			{
				const obj_archive *arc = input->Archives[arcI];
				for (uint32_t symI = 0; symI < arc->NumSymbols; symI++)
				{
					obj_archive_symbol *sym = &arc->Symbols[symI];
					if (!strcmp(sym->Name, ext->Name))
					{
						bool found = false;
						const obj_file *obj = &arc->Members[sym->MemberIndex].ObjectFile;
						for (uint32_t i = 0; i < numObjToProcess; i++)
						{
							if (objToProcess[numObjToProcess] == obj)
								goto arc_sym_found;
						}
						objToProcess[numObjToProcess] = obj;
						numObjToProcess++;
						goto arc_sym_found;
					}
				}
			}
arc_sym_found: {}
		}

		if (numObjToProcess == 0 && !generatedDll)
		{
			CreateDllObject(&genDllObjFile, genDllImports, numDllImports);
			objToProcess[numObjToProcess] = &genDllObjFile;
			numObjToProcess++;
			generatedDll = true;
		}
	}

	link_final_section *finalSections = (link_final_section*)calloc(sizeof(link_final_section), 1024);
	uint32_t numFinalSections = 0;

	for (uint32_t objI = 0; objI < numLinkObjects; objI++)
	{
		link_obj *lobj = &linkObjects[objI];
		for (uint32_t secI = 0; secI < lobj->ObjFile->NumSections; secI++)
		{
			link_section *lsec = &lobj->Sections[secI];
			const obj_section *sec = lsec->ObjSection;
			if (sec->Flags & SectionNoLink)
				continue;

			uint32_t nameLen = 0;
			while (sec->Name[nameLen] != '$' && sec->Name[nameLen] != '\0')
				nameLen++;

			link_final_section *fsec = NULL;
			for (uint32_t i = 0; i < numFinalSections; i++)
			{
				uint32_t nlen = (uint32_t)strlen(finalSections[i].Name);
				if (nlen == nameLen && !memcmp(sec->Name, finalSections[i].Name, nlen))
				{
					fsec = &finalSections[i];
					break;
				}
			}

			if (fsec == NULL)
			{
				fsec = &finalSections[numFinalSections];
				fsec->Name = AllocStrLen(sec->Name, nameLen);
				fsec->Sections = (link_section**)calloc(sizeof(link_section*), 1024);
				fsec->NumSections = 0;
				fsec->Flags = sec->Flags;
				fsec->VirtualAlignment = 4096;
				numFinalSections++;
			}
			else
			{
				Assert(fsec->Flags == sec->Flags);
			}

			fsec->Sections[fsec->NumSections] = lsec;
			fsec->NumSections++;
			if (sec->VirtualAlignment > fsec->VirtualAlignment)
				fsec->VirtualAlignment = sec->VirtualAlignment;
			fsec->TotalDataSize += sec->DataSize;
		}
	}

	for (uint32_t fsecI = 0; fsecI < numFinalSections; fsecI++)
	{
		link_final_section *fsec = &finalSections[fsecI];
		qsort(fsec->Sections, fsec->NumSections, sizeof(link_section*), CompareSectionsInFinalSection);
	}

	obj_file *obj = output->Object;
	obj->FileType = ObjFileExecutable;

	obj->ImageBase = input->ImageBase;

	obj->NumSections = numFinalSections;
	obj->Sections = (obj_section*)calloc(sizeof(obj_section), numFinalSections);

	uint32_t virtualAddress = 4096;

	for (uint32_t fsecI = 0; fsecI < numFinalSections; fsecI++)
	{
		obj_section *sec = &obj->Sections[fsecI];
		link_final_section *fsec = &finalSections[fsecI];

		sec->Name = fsec->Name;
		sec->Flags = fsec->Flags;
		sec->VirtualAlignment = fsec->VirtualAlignment;

		uint32_t maxSize = fsec->TotalDataSize + fsec->NumSections * fsec->VirtualAlignment;
		char *data = (char*)malloc(maxSize);

		virtualAddress = AlignValue(virtualAddress, fsec->VirtualAlignment);
		fsec->VirtualAddress = virtualAddress;
		sec->VirtualAddress = virtualAddress;

		uint32_t pos = 0;

		uint8_t fillByte = sec->Flags & SectionHasCode ? 0xCC : 0x00;

		for (uint32_t secI = 0; secI < fsec->NumSections; secI++)
		{
			link_section *lins = fsec->Sections[secI];
			const obj_section *ins = lins->ObjSection;

			uint32_t newPos = AlignValue(pos, ins->VirtualAlignment);
			memset(data + pos, fillByte, newPos - pos);
			pos = newPos;

			lins->OffsetInSection = pos;
			lins->VirtualAddress = virtualAddress + pos;

			memcpy(data + pos, ins->Data, ins->DataSize);
			pos += ins->VirtualSize;
		}

		sec->Data = data;
		sec->DataSize = pos;
		sec->VirtualSize = pos;
		virtualAddress += pos;
	}

	for (uint32_t objI = 0; objI < numLinkObjects; objI++)
	{
		link_obj *lobj = &linkObjects[objI];
		const obj_file *obj = lobj->ObjFile;

		for (uint32_t symI = 0; symI < obj->NumSymbols; symI++)
		{
			const obj_symbol *sym = &obj->Symbols[symI];
			link_symbol *lsym  = &lobj->Symbols[symI];

			if (sym->Flags & ObjSymbolDefine)
			{
				lsym->VirtualAddress = lobj->Sections[sym->DefinedInSection].VirtualAddress + sym->Address;
				if (sym->Flags & ObjSymbolExternal)
				{
					externs[lsym->ExternIndex].VirtualAddress = lsym->VirtualAddress;
				}
			}
		}
	}

	for (uint32_t objI = 0; objI < numLinkObjects; objI++)
	{
		link_obj *lobj = &linkObjects[objI];
		const obj_file *obj = lobj->ObjFile;

		for (uint32_t symI = 0; symI < obj->NumSymbols; symI++)
		{
			const obj_symbol *sym = &obj->Symbols[symI];
			link_symbol *lsym  = &lobj->Symbols[symI];

			if (!(sym->Flags & ObjSymbolDefine))
			{
				if (sym->Flags & ObjSymbolExternal)
				{
					lsym->VirtualAddress = externs[lsym->ExternIndex].VirtualAddress;
				}
			}
		}
	}

	for (uint32_t fsecI = 0; fsecI < numFinalSections; fsecI++)
	{
		obj_section *sec = &obj->Sections[fsecI];
		link_final_section *fsec = &finalSections[fsecI];

		for (uint32_t secI = 0; secI < fsec->NumSections; secI++)
		{
			link_section *lins = fsec->Sections[secI];
			const obj_section *ins = lins->ObjSection;
			link_obj *lobj = lins->Obj;

			char *ptr = (char*)sec->Data + lins->OffsetInSection;
			for (uint32_t reI = 0; reI < ins->NumRelocations; reI++)
			{
				const obj_relocation *reloc = &ins->Relocations[reI];
				link_symbol *lsym = &lobj->Symbols[reloc->SymbolIndex];

				char *p = ptr + reloc->Address;
				switch (reloc->Type)
				{
					case IMAGE_REL_AMD64_ADDR64:
						*(uint64_unalgined_le*)p = *(uint64_unalgined_le*)p + lsym->VirtualAddress + obj->ImageBase;
						break;
					case IMAGE_REL_AMD64_ADDR32:
						*(uint32_unalgined_le*)p = *(uint32_unalgined_le*)p + lsym->VirtualAddress + obj->ImageBase;
						break;
					case IMAGE_REL_AMD64_ADDR32NB:
						*(uint32_unalgined_le*)p = *(uint32_unalgined_le*)p + lsym->VirtualAddress;
						break;
					case IMAGE_REL_AMD64_REL32:
						*(uint32_unalgined_le*)p = *(uint32_unalgined_le*)p + (lsym->VirtualAddress - (lins->VirtualAddress + reloc->Address + 4));
						break;
					case IMAGE_REL_AMD64_REL32_1:
						*(uint32_unalgined_le*)p = *(uint32_unalgined_le*)p + (lsym->VirtualAddress - (lins->VirtualAddress + reloc->Address + 4 + 1));
						break;
					case IMAGE_REL_AMD64_REL32_2:
						*(uint32_unalgined_le*)p = *(uint32_unalgined_le*)p + (lsym->VirtualAddress - (lins->VirtualAddress + reloc->Address + 4 + 2));
						break;
					case IMAGE_REL_AMD64_REL32_3:
						*(uint32_unalgined_le*)p = *(uint32_unalgined_le*)p + (lsym->VirtualAddress - (lins->VirtualAddress + reloc->Address + 4 + 3));
						break;
					case IMAGE_REL_AMD64_REL32_4:
						*(uint32_unalgined_le*)p = *(uint32_unalgined_le*)p + (lsym->VirtualAddress - (lins->VirtualAddress + reloc->Address + 4 + 4));
						break;
					case IMAGE_REL_AMD64_REL32_5:
						*(uint32_unalgined_le*)p = *(uint32_unalgined_le*)p + (lsym->VirtualAddress - (lins->VirtualAddress + reloc->Address + 4 + 5));
						break;
					case IMAGE_REL_AMD64_SECTION:
						// TODO
						break;
					case IMAGE_REL_AMD64_SECREL:
						*(uint32_unalgined_le*)p = *(uint32_unalgined_le*)p + (lsym->VirtualAddress - lins->VirtualAddress);
						break;
				}

			}
		}
	}

	obj->FilePointers = (obj_file_pointer*)calloc(sizeof(obj_file_pointer), ObjFilePointerCount);

	for (uint32_t objI = 0; objI < numLinkObjects; objI++)
	{
		link_obj *lobj = &linkObjects[objI];
		const obj_file *objf = lobj->ObjFile;

		for (uint32_t symI = 0; symI < objf->NumSymbols; symI++)
		{
			obj_symbol *sym = &objf->Symbols[symI];

			if (!strcmp(sym->Name, input->EntryPointName))
			{
				obj->FilePointers[ObjFilePointerToEntryPoint].VirtualAddress = lobj->Symbols[symI].VirtualAddress;
			}

			for (uint32_t ptrI = 0; ptrI < ArrayCount(objFilePointerSymbol); ptrI++)
			{
				const char *symName = objFilePointerSymbol[ptrI];
				if (symName && !strcmp(sym->Name, symName))
				{
					obj->FilePointers[ptrI].VirtualAddress = lobj->Symbols[symI].VirtualAddress;
				}
			}
		}
	}
}

TestCase(ExperimentLinkWin32)
{
	obj_file mainObj = { 0 };
	obj_file crtObj = { 0 };
	obj_archive user32Arc = { 0 };
	obj_archive kernel32Arc = { 0 };

	{
		char *fileData;
		size_t fileSize;

		TestReadFullFileFromData("freestanding/crt.obj", (void**)&fileData, &fileSize);
		crtObj.Name = "freestanding/crt.obj";
		ReadCoffObject(&crtObj, fileData, fileSize);

		free(fileData);
	}

	{
		char *fileData;
		size_t fileSize;

		TestReadFullFileFromData("freestanding/main.obj", (void**)&fileData, &fileSize);
		mainObj.Name = "freestanding/main.obj";
		ReadCoffObject(&mainObj, fileData, fileSize);

		free(fileData);
	}

	{
		char *fileData;
		size_t fileSize;

		TestReadFullFile("C:\\Program Files (x86)\\Windows Kits\\8.0\\Lib\\win8\\um\\x64\\user32.lib", (void**)&fileData, &fileSize);
		ReadCoffArchive(&user32Arc, fileData, fileSize);

		free(fileData);
	}

	{
		char *fileData;
		size_t fileSize;

		TestReadFullFile("C:\\Program Files (x86)\\Windows Kits\\8.0\\Lib\\win8\\um\\x64\\kernel32.lib", (void**)&fileData, &fileSize);
		ReadCoffArchive(&kernel32Arc, fileData, fileSize);

		free(fileData);
	}

	const obj_file *lobjs[] = {
		&mainObj,
		&crtObj,
	};

	const obj_archive *larcs[] = {
		&user32Arc,
		&kernel32Arc,
	};

	obj_file out = { };
	link_output lout = { };
	lout.Object = &out;

	link_input lin = { };
	lin.Objects = lobjs;
	lin.NumObjects = ArrayCount(lobjs);
	lin.Archives = larcs;
	lin.NumArchives = ArrayCount(larcs);
	lin.ImageBase = 0x00400000;
	lin.EntryPointName = "mainCRTStartup";

	Link(&lout, &lin);

	{
		void *exeCoff = calloc(1024, 1024);
		uint32_t exeCoffSz = WriteCoffObject(&out, exeCoff, 1024*1024);
		TestWriteFullFileToTemp("test.exe", exeCoff, exeCoffSz);
	}
}

