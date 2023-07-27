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

}

void PE32::parse_dos_header()
{
	
	fseek(pe_fp, 0, SEEK_SET);
	fread(&pe_dos_header, sizeof(___IMAGE_DOS_HEADER), 1, pe_fp);
	// ���ﲻ��Ҫ�������ֽ�������Ϊ֮ǰ�Ѿ����ù� `pe_validate()` �ˣ�
	// �������һ���ܹ����� `sizeof(___IMAGE_DOS_HEADER)` ���ֽ�

}

void PE32::parse_dos_stub()
{

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
	nt_headers_offset = pe_dos_header.e_lfanew;

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
