#pragma once
#include "pe-init.h"
#include "pe-custom.h"

class PE32 {
public:
	PE32(char*, FILE*);

	void print_info();

private:
	// �����ĳ�Ա����
	char* file_path;
	FILE* pe_fp;

	// PE���ͷ
	___IMAGE_DOS_HEADER         pe_dos_header;
	___IMAGE_NT_HEADERS32       pe_nt_headers_32;
	___PIMAGE_OPTIONAL_HEADER32 nt_optional_headers;
	___PIMAGE_SECTION_HEADER    section_headers;
	___PIMAGE_IMPORT_DESCRIPTOR import_dir_table_entries;
	___IMAGE_EXPORT_DIRECTORY   export_dir_table;
	___PIMAGE_BASE_RELOCATION   basereloc_table;
	___IMAGE_RESOURCE_DIRECTORY resource_dir_root;

	// PE���ͷ�е�ƫ�����ͱ���
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

	// ��������
	DWORD import_dir_table_entries_num;
	DWORD basereloc_table_num;

	// ��Rich headers�йص���ر���
	RICH_HEADER rich_headers;

	// ��������������ת����ص�ַ
	DWORD va_to_raw(DWORD);

	// ������صĺ���
	void parse_file();
	void parse_dos_header();
	void parse_dos_stub();
	void parse_nt_headers();
	void parse_section_headers();
	void parse_import_directory();
	void parse_export_directory();
	void parse_basereloc_table();
	void parse_resources_table();

	// ��ӡ��صĺ���
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