#pragma once
#include "pe-init.h"

class PE32 {
public:
	PE32(char*, FILE*);

	void print_info();

private:
	// �����ĳ�Ա����
	char* file_path;
	FILE* pe_fp;

	// PE���ͷ
	___IMAGE_DOS_HEADER   pe_dos_header;
	___IMAGE_NT_HEADERS32 pe_nt_headers_32;

	// PE���ͷ�е�ƫ����
	LONG nt_headers_offset;

	// ������صĺ���
	void parse_file();
	void parse_dos_header();
	void parse_dos_stub();
	void parse_nt_headers();
	void parse_section_headers();


	// ��ӡ��صĺ���
	void print_file_info();
	void print_dos_header_info();
	void print_dos_stub_info();
	void print_nt_headers_info();
	void print_section_headers_info();


};