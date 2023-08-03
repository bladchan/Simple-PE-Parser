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
	print_import_table_info();
	print_export_table_info();
	print_basereloc_table_info();
}

DWORD PE32::va_to_raw(DWORD va)
{
	int i, offset;

	// ���ҵ���va��������һ��section
	for (i = 0; i < nt_sections_cnt; i++) {
		if (va >= section_headers[i].VirtualAddress &&
			va < section_headers[i].VirtualAddress + section_headers[i].Misc.VirtualSize) {
			break;
		}
	}

	if (i == nt_sections_cnt) {
		fprintf(stderr, "Error: VA is out of bound! Bad PE file!\n");
		exit(-1);
	}

	// ��ַת��
	offset = va - section_headers[i].VirtualAddress;
	return section_headers[i].PointerToRawData + offset;

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

	// ����Import directory
	parse_import_directory();

	// ����Export directory
	parse_export_directory();

	// ����Base Relocation Table
	parse_basereloc_table();

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
	import_dir_table_rva = nt_optional_headers->DataDirectory[___IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	import_dir_table_size = nt_optional_headers->DataDirectory[___IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	export_dir_table_rva = nt_optional_headers->DataDirectory[___IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	export_dir_table_size = nt_optional_headers->DataDirectory[___IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	basereloc_dir_table_rva = nt_optional_headers->DataDirectory[___IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	basereloc_dir_table_size = nt_optional_headers->DataDirectory[___IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

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

void PE32::parse_import_directory()
{
	if (!import_dir_table_size || !import_dir_table_rva) return;

	DWORD raw_offset, entry_num, read_size;

	// �ȼ��import_dir_table_size�ĺϷ��ԣ��ܾ��Ƿ�PE�ļ�
	if (import_dir_table_size % sizeof(___IMAGE_IMPORT_DESCRIPTOR) != 0) {
		fprintf(stderr, "Error: Wrong Import Directory size. Bad PE file!\n");
		exit(-1);
	}

	entry_num = import_dir_table_size / sizeof(___IMAGE_IMPORT_DESCRIPTOR);
	// ������Ҫע��һ�£�����Ŀ¼�����һ��ʵ��Ϊȫ0���
	// ������ʵû��Ҫ��ȡ���һ��ʵ�������
	entry_num = entry_num - 1;

	if (entry_num > 0xffff) {
		fprintf(stderr, "Error: Too many import entries!");
		exit(-1);
	}

	raw_offset = va_to_raw(import_dir_table_rva);
	fseek(pe_fp, raw_offset, SEEK_SET);

	import_dir_table_entries = (___PIMAGE_IMPORT_DESCRIPTOR)malloc(sizeof(___IMAGE_IMPORT_DESCRIPTOR) * entry_num);
	if (!import_dir_table_entries) {
		fprintf(stderr, "Error: Import_dir_table malloc failed!\n");
		exit(-1);
	}
	read_size = fread(import_dir_table_entries, sizeof(___IMAGE_IMPORT_DESCRIPTOR), entry_num, pe_fp);

	if (read_size != entry_num) {
		fprintf(stderr, "Error: Bad PE file!\n");
		exit(-1);
	}

	import_dir_table_entries_num = entry_num;

}

void PE32::parse_export_directory()
{
	size_t read_size;
	if (!export_dir_table_size || !export_dir_table_rva) return;

	fseek(pe_fp, va_to_raw(export_dir_table_rva), SEEK_SET);
	read_size = fread(&export_dir_table, sizeof(___IMAGE_EXPORT_DIRECTORY), 1, pe_fp);
	if (read_size != 1) {
		fprintf(stderr, "Error: Bad PE file!\n");
		exit(-1);
	}

	// ������������print����ȥ���:))

}

void PE32::parse_basereloc_table()
{
	size_t read_size;
	DWORD basereloc_offset, basereloc_entry_num, i;
	int left_size;
	___IMAGE_BASE_RELOCATION tmp;

	if (!basereloc_dir_table_rva || !basereloc_dir_table_size) return;

	basereloc_offset = va_to_raw(basereloc_dir_table_rva);
	fseek(pe_fp, basereloc_offset, SEEK_SET);
	left_size = basereloc_dir_table_size;
	basereloc_entry_num = 0;
	
	while (1) {
		
		read_size = fread(&tmp, sizeof(___IMAGE_BASE_RELOCATION), 1, pe_fp);
		if (read_size != 1) {
			fprintf(stderr, "Error: Bad PE file!\n");
			exit(-1);
		}

		if (!tmp.VirtualAddress && !tmp.SizeOfBlock) break;

		basereloc_entry_num++;
		left_size -= tmp.SizeOfBlock;
		if (left_size < 0) {
			fprintf(stderr, "Error: Out of base relocation table's size. Maybe Bad PE file!\n");
			exit(-1);
		}
		
		basereloc_offset += tmp.SizeOfBlock;
		fseek(pe_fp, basereloc_offset, SEEK_SET);

	}

	if (basereloc_entry_num > 0xFFFFFF) {
		fprintf(stderr, "Error: Too many base relocation entries!\n");
		exit(-1);
	}

	basereloc_table_num = basereloc_entry_num;

	basereloc_table =
		(___PIMAGE_BASE_RELOCATION)malloc(sizeof(___IMAGE_BASE_RELOCATION) * basereloc_entry_num);
	if (!basereloc_table) {
		fprintf(stderr, "Error: Basereloc_table malloc failed!\n");
		exit(-1);
	}

	basereloc_offset = va_to_raw(basereloc_dir_table_rva);
	fseek(pe_fp, basereloc_offset, SEEK_SET);

	for (i = 0; i < basereloc_entry_num; i++) {
		fread(&basereloc_table[i], sizeof(___IMAGE_BASE_RELOCATION), 1, pe_fp);
		basereloc_offset += basereloc_table[i].SizeOfBlock;
		fseek(pe_fp, basereloc_offset, SEEK_SET);
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
	nt_headers_machine = pe_nt_headers_32.FileHeader.Machine;
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

void PE32::print_import_table_info()
{
	if (!import_dir_table_size || !import_dir_table_rva) {
		fprintf(stdout, "====No import table===\n\n");
		fprintf(stdout, "\n==========END=========\n\n");
		return;
	}

	DWORD i, j, name_size, name_rva;
	char* name_tmp, ch = 1;
	___IMAGE_IMPORT_BY_NAME hint;

	fprintf(stdout, "======Import table====\n\n");

	for (i = 0; i < import_dir_table_entries_num; i++) {

		name_rva = import_dir_table_entries[i].Name;
		fseek(pe_fp, va_to_raw(name_rva), SEEK_SET);
		
		// ȷ�����ֵĳ���
		name_size = 0;
		ch = fgetc(pe_fp);
		while (ch != EOF && ch != 0) {
			if (++name_size > 256) { 
				// �ܾ����ƴ���256��DLL���֣��ԷǷ�PE�ļ�飩
				fprintf(stderr, "Error: DLL's name too long?!\n");
				exit(-1);
			}
			ch = fgetc(pe_fp);
		}
		
		name_tmp = (char*)malloc(name_size + 1);
		if (!name_tmp) {
			fprintf(stderr, "Error: Name_tmp malloc failed!\n");
			exit(-1);
		}
		name_tmp[name_size] = 0;
		fseek(pe_fp, va_to_raw(name_rva), SEEK_SET);
		fread(name_tmp, sizeof(char), name_size, pe_fp);
		fprintf(stdout, "  * %s:\n\n", name_tmp);
		free(name_tmp);
		fprintf(stdout, "    - Import Lookup Table (ILT): 0x%X (RVA), 0x%X (RAW)\n",
			import_dir_table_entries[i].DUMMYUNIONNAME.OriginalFirstThunk,
			va_to_raw(import_dir_table_entries[i].DUMMYUNIONNAME.OriginalFirstThunk));
		fprintf(stdout, "    - Import Address Table (IAT): 0x%X (RVA), 0x%X (RAW)\n",
			import_dir_table_entries[i].FirstThunk,
			va_to_raw(import_dir_table_entries[i].FirstThunk));
		fprintf(stdout, "    - Bound?: %s\n", import_dir_table_entries[i].TimeDateStamp ? "TRUE" : "FALSE");


		// ILT��IATֵ��PE����ǰ��һ���ģ�����ȡ��һ������
		// �������庯����
	    // https://learn.microsoft.com/zh-cn/windows/win32/debug/pe-format#the-idata-section

		fprintf(stdout, "    - Entries: \n\n");

		for (j = 0; ; j++) {
			fseek(pe_fp, va_to_raw(import_dir_table_entries[i].FirstThunk + j * sizeof(DWORD)), SEEK_SET);
			fread(&name_rva, sizeof(DWORD), 1, pe_fp);
			if (name_rva == 0) break;
			if (!(name_rva & 0x80000000)) {
				fseek(pe_fp, va_to_raw(name_rva), SEEK_SET);
				fread(&hint, sizeof(___IMAGE_IMPORT_BY_NAME), 1, pe_fp);
				hint.Name[99] = 0; // ��ֹԽ���
				fprintf(stdout, "       [%02d] Name: %s\n            Hint: 0x%X\n            Call via: 0x%X (RVA)\n",
					j + 1, hint.Name, hint.Hint, 
					import_dir_table_entries[i].FirstThunk + j * sizeof(DWORD));
			}
			else {
				// ������ŵ���
				fprintf(stdout, "       [%02d] Ordinal: 0x%X\n", j + 1, name_rva & 0xffff);
			}
		}
		fprintf(stdout, "\n");
	}

	fprintf(stdout, "\n==========END=========\n\n");

}

void PE32::print_export_table_info()
{
	size_t read_size;
	DWORD name_offset, name_size, i;
	DWORD* name_p_table, *export_address_table;
	WORD* ord_table;
	char *name_tmp, ch;
	PEXPORT_ENTRY export_entries;

	if (!export_dir_table_size || !export_dir_table_rva) {
		fprintf(stdout, "====No export table===\n\n");
		fprintf(stdout, "\n==========END=========\n\n");
		return;
	}

	fprintf(stdout, "======Export table====\n\n");

	// �Ƚ�������Ŀ¼��
	// 1. �Ƚ�������������
	name_offset = va_to_raw(export_dir_table.Name);
	fseek(pe_fp, name_offset, SEEK_SET);
	
	name_size = 0;
	ch = fgetc(pe_fp);
	while (ch != EOF && ch != 0) {
		if (++name_size > 256) {
			fprintf(stderr, "Error: DLL's name too long?!\n");
			exit(-1);
		}
		ch = fgetc(pe_fp);
	}

	name_tmp = (char*)malloc(name_size + 1);
	if (!name_tmp) {
		fprintf(stderr, "Error: Name_tmp malloc failed!\n");
		exit(-1);
	}
	name_tmp[name_size] = 0;
	fseek(pe_fp, name_offset, SEEK_SET);
	fread(name_tmp, sizeof(char), name_size, pe_fp);

	fprintf(stdout, " - Name: %s (raw offset: 0x%X)\n", name_tmp, name_offset);
	free(name_tmp);

	// 2.��������������
	// �ȹ����Զ����ʵ��

	if (export_dir_table.NumberOfFunctions < export_dir_table.NumberOfNames) {
		fprintf(stderr, "Error: Seriously?! Bad PE file!\n");
		exit(-1);
	}

	if (export_dir_table.NumberOfFunctions > 0xFFFF) {
		fprintf(stderr, "Error: Too many functions exported (>65535).\n");
		exit(-1);
	}

	export_entries = (PEXPORT_ENTRY)malloc(sizeof(EXPORT_ENTRY) * export_dir_table.NumberOfFunctions);

	// ����������ַ��
	export_address_table = (DWORD*)malloc(sizeof(DWORD) * export_dir_table.NumberOfFunctions);
	fseek(pe_fp, va_to_raw(export_dir_table.AddressOfFunctions), SEEK_SET);
	read_size = fread(export_address_table, sizeof(DWORD), export_dir_table.NumberOfFunctions, pe_fp);

	if (read_size ^ export_dir_table.NumberOfFunctions) {
		fprintf(stderr, "Error: Bad PE file!\n");
		exit(-1);
	}

	// ��ʼ��
	for (i = 0; i < export_dir_table.NumberOfFunctions; i++) {
		export_entries[i].ordinal = export_dir_table.Base + i;
		export_entries[i].function_rva = export_address_table[i];
		export_entries[i].name_rva = 0;
	}

	free(export_address_table);

	// ��������ָ������ű�

	name_p_table = (DWORD*)malloc(sizeof(DWORD) * export_dir_table.NumberOfNames);
	ord_table = (WORD*)malloc(sizeof(WORD) * export_dir_table.NumberOfNames);

	if (!name_p_table || !ord_table) {
		fprintf(stderr, "Error: Name_p_table or ord_table malloc failed!\n");
		exit(-1);
	}

	fseek(pe_fp, va_to_raw(export_dir_table.AddressOfNames), SEEK_SET);
	read_size = fread(name_p_table, sizeof(DWORD), export_dir_table.NumberOfNames, pe_fp);

	fseek(pe_fp, va_to_raw(export_dir_table.AddressOfNameOrdinals), SEEK_SET);
	read_size ^= fread(ord_table, sizeof(WORD), export_dir_table.NumberOfNames, pe_fp);

	if (read_size) {
		fprintf(stderr, "Error: Bad PE file!\n");
		exit(-1);
	}
	
	for (i = 0; i < export_dir_table.NumberOfNames; i++) {

		WORD offset = *(WORD*)(ord_table + i);

		if (offset > export_dir_table.NumberOfFunctions) {
			fprintf(stderr, "Error: Bad PE file!\n");
			exit(-1);
		}

		export_entries[offset].name_rva = *(DWORD*)(name_p_table + i);
		name_offset = va_to_raw(*(DWORD*)(name_p_table + i));
		fseek(pe_fp, name_offset, SEEK_SET);

		name_size = 0;
		ch = fgetc(pe_fp);
		while (ch != EOF && ch != 0) {
			if (++name_size > 99) {
				fprintf(stderr, "Error: Function's name too long?!\n");
				exit(-1);
			}
			ch = fgetc(pe_fp);
		}

		name_tmp = (char*)malloc(name_size + 1);
		if (!name_tmp) {
			fprintf(stderr, "Error: Name_tmp malloc failed!\n");
			exit(-1);
		}
		name_tmp[name_size] = 0;
		fseek(pe_fp, name_offset, SEEK_SET);
		fread(name_tmp, sizeof(char), name_size, pe_fp);

		memcpy(export_entries[offset].name, name_tmp, name_size + 1);
		free(name_tmp);

	}
	
	free(name_p_table);
	free(ord_table);

	// ��ӡ
	fprintf(stdout, " - Export Entries:\n\n");
	for (i = 0; i < export_dir_table.NumberOfFunctions; i++) {
		
		if (!export_entries[i].function_rva)
			memcpy(export_entries[i].name, "-", 2);	
		else
			export_entries[i].name[99] = 0;  // ��ֹԽ���

		fprintf(stdout, "    [%02d] Ordinal: %d\n"
			"           Function RVA: 0x%X\n"
			"           Name: %s (RVA: 0x%X)\n\n",
			i + 1, export_entries[i].ordinal, export_entries[i].function_rva, 
			export_entries[i].name, export_entries[i].name_rva);
	}
	

	free(export_entries);

	fprintf(stdout, "\n==========END=========\n\n");

}

void PE32::print_basereloc_table_info()
{
	DWORD i, j, basereloc_offset, block_entries_num;
	WORD  value;
	if (!basereloc_dir_table_rva || !basereloc_dir_table_size) {
		fprintf(stdout, "===No base relocation table===\n\n");
		fprintf(stdout, "\n==========END=========\n\n");
		return;
	}

	fprintf(stdout, "===Base relocation table===\n\n");

	fseek(pe_fp, va_to_raw(basereloc_dir_table_rva), SEEK_SET);

	for (i = 0; i < basereloc_table_num; i++) {

		block_entries_num = (basereloc_table[i].SizeOfBlock - 8) / 2;

		fprintf(stdout, "  * Block %02d:\n\n", i + 1);
		fprintf(stdout, "    - Page RVA: 0x%X\n", basereloc_table[i].VirtualAddress);
		fprintf(stdout, "    - Block Size: 0x%X\n", basereloc_table[i].SizeOfBlock);
		fprintf(stdout, "    - Entries [total %d]:\n\n", block_entries_num);

		fseek(pe_fp, 8, SEEK_CUR);

		for (j = 0; j < block_entries_num; j++) {
			// ��ע�⣬fread����0x1A (ctrl-Z) ��ֹ�������ļ���Ҫ�Զ����Ƶ���ʽ��
			fread(&value, sizeof(WORD), 1, pe_fp);
			fprintf(stdout, "       [%03d] Value: 0x%04X\n", j+1, value);
			fprintf(stdout, "             Type : %s\n", translate_block_entry_types((value & 0xf000) >> 12, nt_headers_machine));
			fprintf(stdout, "  Offset from Page: 0x%X\n", value & 0x0fff);
			fprintf(stdout, "         Reloc RVA: 0x%X\n\n", basereloc_table[i].VirtualAddress + (value & 0x0fff));
		}

	}

	fprintf(stdout, "\n==========END=========\n\n");

}
