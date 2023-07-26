#include "pe-init.h"

int pe_validate(FILE* file) {
	/*  
	*  此函数用于检查传入文件是否为PE文件
	*  参数1是传入的PE文件FILE指针
	*  返回值：-1表示文件损坏；0表示不是合法的PE文件；否则返回PE文件的类型（32 -> PE32; 64 -> PE+/PE32+; 1 -> ROM?）
	*/

	__IMAGE_DOS_HEADER dos_header;
	DWORD sig;
	WORD pefile_type;

	fseek(file, 0, SEEK_SET);
	size_t read_size = fread(&dos_header, sizeof(__IMAGE_DOS_HEADER), 1, file);

	if (read_size != 1)
		return -1;

	// 检查PE文件的MS标志
	if (dos_header.e_magic != ___IMAGE_DOS_SIGNATURE) {
		fprintf(stderr, "Not a PE file.\n");
		return 0;
	}

	// 检查NT Header的PE标志
	if (fseek(file, dos_header.e_lfanew, SEEK_SET)) return -1;
	fread(&sig, sizeof(DWORD), 1, file);
	if (sig != ___IMAGE_NT_SIGNATURE) {
		fprintf(stderr, "Not a PE file.\n");
		return 0;
	}

	if (fseek(file, dos_header.e_lfanew + sizeof(DWORD) + sizeof(___IMAGE_FILE_HEADER), SEEK_SET)) return -1;
	read_size = fread(&pefile_type, sizeof(WORD), 1, file);

	if (read_size != 1) return -1;
	// 匹配PE文件的类型
	switch (pefile_type) {
		case ___IMAGE_NT_OPTIONAL_HDR32_MAGIC:
			return 32;
		case ___IMAGE_NT_OPTIONAL_HDR64_MAGIC:
			return 64;
		case ___IMAGE_ROM_OPTIONAL_HDR_MAGIC:
			return 1;
		default: {
			fprintf(stderr, "Error when parsing ___IMAGE_OPTIONAL_HEADER.Magic. Unknown Type.\n");
			return 0;
		}
	}

	return -1;
}