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
	print_dos_stub_info();
	print_nt_headers_info();
	print_section_headers_info();
}

void PE32::parse_file()
{
	// ����DOS Header
	parse_dos_header();

	// ����Rich Headers
	parse_dos_stub();

	// ����NT Headers
	parse_nt_headers();

	// ����Section Headers
	parse_section_headers();

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
	char* dos_stub_buffer, * buf_ptr;
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
			if (i + 8 >= (int)alloc_size) {
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
		exit(-1);
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

	// ɾ���ײ�"DanS + 3padding"��β��"Rich + XOR key"
	if((alloc_size - 24) % 8 == 0 && (alloc_size - 24) / 8 <= 0xffff)  // ����һ�����rich header��
		rich_headers.entries_num = (alloc_size - 24) / 8;
	else {
		fprintf(stderr, "Error: Bad PE file!\n");
		exit(-1);
	}

	// ����ͷ��ʵ��
	rich_headers.entries = (PRICH_HEADER_ENTRY)malloc(sizeof(RICH_HEADER_ENTRY) * rich_headers.entries_num);
	if (!rich_headers.entries) {
		fprintf(stderr, "Error: Rich_headers.entries malloc failed!\n");
		exit(-1);
	}

	buf_ptr = rich_headers.raw_data.data_ptr + 16;
	for (i = 0; i < rich_headers.entries_num; i++) {

		DWORD* temp = (DWORD*)buf_ptr;
		rich_headers.entries[i].r_prod_id = (*temp >> 16) ^ (xor_key >> 16);
		rich_headers.entries[i].r_build_id = (*temp & 0x0000ffff) ^ (xor_key & 0x0000ffff);
		temp++;
		rich_headers.entries[i].r_count = *temp ^ xor_key;
		buf_ptr += 8;

	}

	rich_headers.exits = true;

	// ����ɾ��raw_data�����rich_headersԭʼ����
	free(rich_headers.raw_data.data_ptr);

}

void PE32::parse_nt_headers()
{
	size_t read_size;

	fseek(pe_fp, nt_headers_offset, SEEK_SET);
	read_size = fread(&pe_nt_headers_32, sizeof(___IMAGE_NT_HEADERS32), 1, pe_fp);

	if (read_size != 1) {
		fprintf(stderr, "Error: Bad PE file!\n");
		exit(-1);
	}

	nt_sections_cnt = pe_nt_headers_32.FileHeader.NumberOfSections;
	nt_optional_header_size = pe_nt_headers_32.FileHeader.SizeOfOptionalHeader;
	nt_characteristics = pe_nt_headers_32.FileHeader.Characteristics;
	nt_optional_headers = &pe_nt_headers_32.OptionalHeader;
	pe_header_size = nt_optional_headers->SizeOfHeaders;

}

void PE32::parse_section_headers()
{
	size_t read_size;

	// ���һ�±߽�
	int start_pos = nt_headers_offset + sizeof(___IMAGE_NT_HEADERS32);
	if (start_pos + nt_sections_cnt * sizeof(___IMAGE_SECTION_HEADER) > pe_header_size) {
		fprintf(stderr, "Error: Out of PE header's size. Bad PE file!\n");
		exit(-1);
	}

	// section_headersΪָ���������Ҫ��̬����ռ�
	section_headers = (___PIMAGE_SECTION_HEADER)malloc(sizeof(___IMAGE_SECTION_HEADER) * nt_sections_cnt);
	if (!section_headers) {
		fprintf(stderr, "Error: Section_headers malloc failed!\n");
		exit(-1);
	}

	fseek(pe_fp, start_pos, SEEK_SET);
	read_size = fread(section_headers, sizeof(___IMAGE_SECTION_HEADER), nt_sections_cnt, pe_fp);
	
	if (read_size != nt_sections_cnt) {
		fprintf(stderr, "Error: Bad PE file!\n");
		exit(-1);
	}

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
	fprintf(stdout, "\n==========END=========\n\n");

}

void PE32::print_dos_stub_info()
{	

	if (!rich_headers.exits) return;

	// ��ӡRich headers����Ϣ
	fprintf(stdout, "=====Rich Headers=====\n\n");
	fprintf(stdout, "%-25s\tBuildID\t\tCount\t\tMeaning\n", "ProductName");
	for (int i = 0; i < rich_headers.entries_num; i++) {
		if (rich_headers.entries[i].r_prod_id >= __PRODID_NAME_NUM) {
			rich_headers.entries[i].r_prod_id = 0; // �Ƿ�ID���ض���Unknow
		}
		fprintf(stdout, "%-25s\t%d\t\t%d\t\t%d.%d.%d\n",
			prod_ids_to_names[rich_headers.entries[i].r_prod_id],
			rich_headers.entries[i].r_prod_id,
			rich_headers.entries[i].r_count,
			rich_headers.entries[i].r_build_id,
			rich_headers.entries[i].r_prod_id,
			rich_headers.entries[i].r_count
		);
	}
	fprintf(stdout, "\n==========END=========\n\n");

}

void PE32::print_nt_headers_info()
{
	WORD temp_c, n, i;

	fprintf(stdout, "======NT Headers======\n\n");

	fprintf(stdout, "PE Signature: 0x%X\n\n", pe_nt_headers_32.Signature);

	fprintf(stdout, "File Header:\n");
	fprintf(stdout, " - Machine: %s (0x%04X)\n", 
		translate_machine(pe_nt_headers_32.FileHeader.Machine),
		pe_nt_headers_32.FileHeader.Machine);
	fprintf(stdout, " - Sections Count: %d\n", nt_sections_cnt);
	// fprintf(stdout, " - Time Date Stamp: %d\n", pe_nt_headers_32.FileHeader.TimeDateStamp);
	fprintf(stdout, " - Size of Optional Header: %d\n", nt_optional_header_size);
	fprintf(stdout, " - Characteristics: 0x%X\n", nt_characteristics);
	// ��һ������Characteritics
	temp_c = nt_characteristics;
	n = 0;
	while (temp_c) {
		if (temp_c & 1) {
			fprintf(stdout, "    - 0x%X:\t %s\n", (1 << n), characteristics_names[n]);
		}
		temp_c = temp_c >> 1;
		n++;
	}

	fprintf(stdout, "\nOptional Header:\n");
	fprintf(stdout, " - Magic: %s (0x%X)\n", translate_nt_optional_header_magic(nt_optional_headers->Magic), nt_optional_headers->Magic);
	fprintf(stdout, " - Size of Code: 0x%X (%d)\n", nt_optional_headers->SizeOfCode, nt_optional_headers->SizeOfCode);
	fprintf(stdout, " - Size of Initialized Data: 0x%X (%d)\n", nt_optional_headers->SizeOfInitializedData, nt_optional_headers->SizeOfInitializedData);
	fprintf(stdout, " - Size of Uninitialized Data: 0x%X (%d)\n", nt_optional_headers->SizeOfUninitializedData, nt_optional_headers->SizeOfUninitializedData);
	fprintf(stdout, " - Entry Point: 0x%X (%d)\n", nt_optional_headers->AddressOfEntryPoint, nt_optional_headers->AddressOfEntryPoint);
	fprintf(stdout, " - Base of Code: 0x%X\n", nt_optional_headers->BaseOfCode);
	fprintf(stdout, " - Desired Image Base: 0x%X\n", nt_optional_headers->ImageBase);
	fprintf(stdout, " - Section Alignment: 0x%X\n", nt_optional_headers->SectionAlignment);
	fprintf(stdout, " - File Alignment: 0x%X\n", nt_optional_headers->FileAlignment);
	fprintf(stdout, " - Size of Image: 0x%X (%d)\n", nt_optional_headers->SizeOfImage, nt_optional_headers->SizeOfImage);
	fprintf(stdout, " - Size of Headers: 0x%X (%d)\n", nt_optional_headers->SizeOfHeaders, nt_optional_headers->SizeOfHeaders);

	fprintf(stdout, " - Data Directory:\n");
	for (i = 0; i < ___IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR; i++) {
		fprintf(stdout, "    - %s ==> Address: 0x%X, Size: 0x%X\n", translate_data_directory(i), nt_optional_headers->DataDirectory[i].VirtualAddress, nt_optional_headers->DataDirectory[i].Size);
	}

	import_dir_table_rva = nt_optional_headers->DataDirectory[___IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

	fprintf(stdout, "\n==========END=========\n\n");

}

void PE32::print_section_headers_info()
{

	int i;

	fprintf(stdout, "====Section Headers===\n");
	fprintf(stdout, "Number of Sections: %d\n\n", nt_sections_cnt);

	for (i = 0; i < nt_sections_cnt; i++) {

		BYTE* section_name = (BYTE*)malloc(___IMAGE_SIZEOF_SHORT_NAME + 1);
		if (!section_name) {
			fprintf(stderr, "Error: Section_name malloc failed!\n");
			exit(-1);
		}
		section_name[___IMAGE_SIZEOF_SHORT_NAME] = 0;
		memcpy(section_name, section_headers[i].Name, ___IMAGE_SIZEOF_SHORT_NAME);

		fprintf(stdout, "  * %s:\n", section_name);
		fprintf(stdout, "    - Virtual Address: 0x%X\n", section_headers[i].VirtualAddress);
		// virtual size �Ǹý���װ�ڵ��ڴ���ܴ�С�����ֵ����SizeOfRawData�����Ĳ�����0x00���
		fprintf(stdout, "    - Virtual Size: 0x%X\n", section_headers[i].Misc.VirtualSize);
		fprintf(stdout, "    - Pointer to Raw Data: 0x%X\n", section_headers[i].PointerToRawData);
		fprintf(stdout, "    - Raw Data's Size: 0x%X\n", section_headers[i].SizeOfRawData);
		fprintf(stdout, "    - Characteristics: 0x%X\n\n", section_headers[i].Characteristics);

	}

	fprintf(stdout, "\n==========END=========\n\n");

}
