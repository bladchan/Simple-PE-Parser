#include "pe-init.h"

int pe_validate(FILE* file) {
	/*  
	*  �˺������ڼ�鴫���ļ��Ƿ�ΪPE�ļ�
	*  ����1�Ǵ����PE�ļ�FILEָ��
	*  ����ֵ��-1��ʾ�ļ��𻵣�0��ʾ���ǺϷ���PE�ļ������򷵻�PE�ļ������ͣ�32 -> PE32; 64 -> PE+/PE32+; 1 -> ROM?��
	*/

	__IMAGE_DOS_HEADER dos_header;
	DWORD sig;
	WORD pefile_type;

	fseek(file, 0, SEEK_SET);
	size_t read_size = fread(&dos_header, sizeof(__IMAGE_DOS_HEADER), 1, file);

	if (read_size != 1)
		return -1;

	// ���PE�ļ���MS��־
	if (dos_header.e_magic != ___IMAGE_DOS_SIGNATURE) {
		fprintf(stderr, "Not a PE file.\n");
		return 0;
	}

	// ���NT Header��PE��־
	if (fseek(file, dos_header.e_lfanew, SEEK_SET)) return -1;
	fread(&sig, sizeof(DWORD), 1, file);
	if (sig != ___IMAGE_NT_SIGNATURE) {
		fprintf(stderr, "Not a PE file.\n");
		return 0;
	}

	if (fseek(file, dos_header.e_lfanew + sizeof(DWORD) + sizeof(___IMAGE_FILE_HEADER), SEEK_SET)) return -1;
	read_size = fread(&pefile_type, sizeof(WORD), 1, file);

	if (read_size != 1) return -1;
	// ƥ��PE�ļ�������
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