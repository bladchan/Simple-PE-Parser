#include "pe32.h"

PE32::PE32(char* path, FILE* fp) : file_path(path), pe_fp(fp) 
{
	if (!fp || pe_validate(fp) != 32) {
		// �����API���ã�ֱ���˳��������̣�
		// ���ܻ����࣬�����ڱ���API��³����
		exit(-1);
	}

	parse_file();

}

void PE32::print_info()
{
	print_dos_header_info();
}

void PE32::parse_file()
{
	// ����DOS Header
	parse_dos_header();

	// ����Rich Headers
	parse_dos_stub();

}

void PE32::parse_dos_header()
{
	
	fseek(pe_fp, 0, SEEK_SET);
	fread(&pe_dos_header, sizeof(___IMAGE_DOS_HEADER), 1, pe_fp);
	// ���ﲻ��Ҫ�������ֽ�������Ϊ֮ǰ�Ѿ����ù� `pe_validate()` �ˣ�
	// �������һ���ܹ����� `sizeof(___IMAGE_DOS_HEADER)` ���ֽ�

	nt_headers_offset = pe_dos_header.e_lfanew;

}

void PE32::parse_dos_stub()
{
	size_t alloc_size;
	char* dos_stub_buffer;
	int i, start, end;
	DWORD xor_key = 0;

	memset(&rich_headers, 0, sizeof(RICH_HEADER));

	// ��ֹmalloc_size_too_big����
	alloc_size = nt_headers_offset - sizeof(__IMAGE_DOS_HEADER);
	if (alloc_size + 1 > 0xffffff) {
		// Really too big! Reject this allocation!
		exit(-1);
	}

	// ����Rich headers
	dos_stub_buffer = (char*)malloc(alloc_size + 1);
	if (!dos_stub_buffer) {
		fprintf(stderr, "Error: Dos_stub_buffer malloc failed\n");
		exit(-1);
	}
	fseek(pe_fp, sizeof(__IMAGE_DOS_HEADER) - 1, SEEK_SET);
	fread(dos_stub_buffer, sizeof(char), alloc_size, pe_fp);
	dos_stub_buffer[alloc_size] = 0;

	// �Ӻ���ǰѰ�� `Rich` ��־
	// �����������Rich headers�Ƕ��뵽4�ֽڵ�
	/*
	for (i = alloc_size - 4; i >= 0; i -= 4) {
		if (*(DWORD*)(dos_stub_buffer + i) == ___IMAGE_RICH_ID) {
			// �ҵ� `Rich`
			xor_key = *(DWORD*)(dos_stub_buffer + i + 4);
			fprintf(stdout, "%x\n", xor_key);
		}
	}
	*/

	for (i = alloc_size - 4; i >= 0; i--) {
		if (dos_stub_buffer[i] == 'R' &&
			dos_stub_buffer[i + 1] == 'i' &&
			dos_stub_buffer[i + 2] == 'c' &&
			dos_stub_buffer[i + 3] == 'h') {
			// �ҵ� `Rich`
			if (i + 8 >= alloc_size) {
				// ����Ǳ�ڵ�Խ�������
				fprintf(stderr, "Detect out bound read. Bad PE file!\n");
				exit(-1);
			}
			xor_key = *(DWORD*)(dos_stub_buffer + i + 4);
			break;
		}
	}
	if (i < 0) {
		// ��PE�ļ����ܾ����޸ĵ�����Rich headers���ܱ�ɾ����
		// Ҳ�п��ܸ�PE�ļ���ʽ����
		fprintf(stdout, "Warning: Cannot find Rich headers. (Ignore)\n");
		rich_headers.exits = false;
		return;
	}

	end = i + 8;

	// Ѱ����ʼ��
	for (i = end - 8; i >= 0; i -= 4) {
		DWORD* temp = (DWORD*)&dos_stub_buffer[i];
		if ((*temp ^ xor_key) == ___IMAGE_RICH_DANS_ID)
			break;
	}
	if (i < 0) {
		fprintf(stderr, "Error: Bad PE file!\n");
		exit(0);
	}

	start = i;

	alloc_size = end - start;
	rich_headers.raw_data.data_ptr = (char*)malloc(alloc_size);
	if (!rich_headers.raw_data.data_ptr) {
		fprintf(stderr, "Error: Data_ptr malloc failed!\n");
		exit(-1);
	}
	rich_headers.raw_data.data_size = alloc_size;
	memcpy(rich_headers.raw_data.data_ptr, dos_stub_buffer + start, alloc_size);
	free(dos_stub_buffer);
	
}

void PE32::parse_section_headers()
{

}

void PE32::parse_nt_headers()
{

}

void PE32::print_file_info()
{

}

void PE32::print_dos_header_info()
{

	// Ϊ�˼򻯣���������ֻ��ӡһЩ��Ҫ��Ϣ
	fprintf(stdout, "======DOS Header======\n\n");
	fprintf(stdout, "Magic number: 0x%04X\n", pe_dos_header.e_magic);
	fprintf(stdout, "File address of new exe header: 0x%X\n", pe_dos_header.e_lfanew);
	fprintf(stdout, "\n==========END==========\n");

}

void PE32::print_dos_stub_info()
{	

}

void PE32::print_nt_headers_info()
{

}

void PE32::print_section_headers_info()
{

}
