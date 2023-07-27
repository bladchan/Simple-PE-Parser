#pragma once
#include "pe-init.h"

class PE32 {
public:
	PE32(char*, FILE*);

	void print_info();

private:
	// 基础的成员变量
	char* file_path;
	FILE* pe_fp;

	// PE相关头
	___IMAGE_DOS_HEADER   pe_dos_header;
	___IMAGE_NT_HEADERS32 pe_nt_headers_32;

	// PE相关头中的偏移量
	LONG nt_headers_offset;

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