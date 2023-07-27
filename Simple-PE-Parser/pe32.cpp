#include "pe32.h"

PE32::PE32(char* path, FILE* fp) : file_path(path), pe_fp(fp) 
{
	if (!fp || pe_validate(fp) != 32) {
		// 错误的API调用，直接退出解析过程！
		// 可能会冗余，仅用于保持API的鲁棒性
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
	// 解析DOS Header
	parse_dos_header();

}

void PE32::parse_dos_header()
{
	
	fseek(pe_fp, 0, SEEK_SET);
	fread(&pe_dos_header, sizeof(___IMAGE_DOS_HEADER), 1, pe_fp);
	// 这里不需要检查读入字节数，因为之前已经调用过 `pe_validate()` 了，
	// 因此这里一定能够读入 `sizeof(___IMAGE_DOS_HEADER)` 个字节

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

	// 为了简化，我们这里只打印一些主要信息
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
