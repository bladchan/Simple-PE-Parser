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
	___PIMAGE_IMPORT_DESCRIPTOR import_dir_table_entries;
	___IMAGE_EXPORT_DIRECTORY   export_dir_table;
	___PIMAGE_BASE_RELOCATION   basereloc_table;
	___IMAGE_RESOURCE_DIRECTORY resource_dir_root;

	// PE相关头中的偏移量和变量
	WORD  nt_headers_machine;
	LONG  nt_headers_offset;
	WORD  nt_sections_cnt;
	WORD  nt_optional_header_size;
	WORD  nt_characteristics;
	DWORD pe_header_size;
	DWORD import_dir_table_rva;
	DWORD import_dir_table_size;
	DWORD export_dir_table_rva;
	DWORD export_dir_table_size;
	DWORD basereloc_dir_table_rva;
	DWORD basereloc_dir_table_size;
	DWORD resource_dir_table_rva;
	DWORD resource_dir_table_size;

	// 辅助变量
	DWORD import_dir_table_entries_num;
	DWORD basereloc_table_num;

	// 与Rich headers有关的相关变量
	RICH_HEADER rich_headers;

	// 辅助函数，用于转化相关地址
	DWORD va_to_raw(DWORD);

	// 解析相关的函数
	void parse_file();
	void parse_dos_header();
	void parse_dos_stub();
	void parse_nt_headers();
	void parse_section_headers();
	void parse_import_directory();
	void parse_export_directory();
	void parse_basereloc_table();
	void parse_resources_table();

	// 打印相关的函数
	void print_file_info();
	void print_dos_header_info();
	void print_dos_stub_info();
	void print_nt_headers_info();
	void print_section_headers_info();
	void print_import_table_info();
	void print_export_table_info();
	void print_basereloc_table_info();
	void print_resources_table_info();

};