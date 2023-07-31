#pragma once
#include "pe-init.h"
#include "pe-custom.h"

class PE32 {
public:
	PE32(char*, FILE*);

	void print_info();

private:
	// 基础的成员变量
	char* file_path;
	FILE* pe_fp;

	// PE相关头
	___IMAGE_DOS_HEADER         pe_dos_header;
	___IMAGE_NT_HEADERS32       pe_nt_headers_32;
	___PIMAGE_OPTIONAL_HEADER32 nt_optional_headers;
	___PIMAGE_SECTION_HEADER    section_headers;

	// PE相关头中的偏移量
	LONG  nt_headers_offset;
	WORD  nt_sections_cnt;
	WORD  nt_optional_header_size;
	WORD  nt_characteristics;
	DWORD pe_header_size;
	DWORD import_dir_table_rva;

	// 与Rich headers有关的相关变量
	RICH_HEADER rich_headers;

	// 解析相关的函数
	void parse_file();
	void parse_dos_header();
	void parse_dos_stub();
	void parse_nt_headers();
	void parse_section_headers();

	// 打印相关的函数
	void print_file_info();
	void print_dos_header_info();
	void print_dos_stub_info();
	void print_nt_headers_info();
	void print_section_headers_info();

};