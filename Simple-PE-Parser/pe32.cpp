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
	print_dos_stub_info();
	print_nt_headers_info();
}

void PE32::parse_file()
{
	// 解析DOS Header
	parse_dos_header();

	// 解析Rich Headers
	parse_dos_stub();

	// 解析NT Headers
	parse_nt_headers();

}

void PE32::parse_dos_header()
{
	
	fseek(pe_fp, 0, SEEK_SET);
	fread(&pe_dos_header, sizeof(___IMAGE_DOS_HEADER), 1, pe_fp);
	// 这里不需要检查读入字节数，因为之前已经调用过 `pe_validate()` 了，
	// 因此这里一定能够读入 `sizeof(___IMAGE_DOS_HEADER)` 个字节

	nt_headers_offset = pe_dos_header.e_lfanew;

}

void PE32::parse_dos_stub()
{
	size_t alloc_size;
	char* dos_stub_buffer, * buf_ptr;
	int i, start, end;
	DWORD xor_key = 0;

	memset(&rich_headers, 0, sizeof(RICH_HEADER));

	// 防止malloc_size_too_big问题
	alloc_size = nt_headers_offset - sizeof(__IMAGE_DOS_HEADER);
	if (alloc_size + 1 > 0xffffff) {
		// Really too big! Reject this allocation!
		exit(-1);
	}

	// 解析Rich headers
	dos_stub_buffer = (char*)malloc(alloc_size + 1);
	if (!dos_stub_buffer) {
		fprintf(stderr, "Error: Dos_stub_buffer malloc failed\n");
		exit(-1);
	}
	fseek(pe_fp, sizeof(__IMAGE_DOS_HEADER) - 1, SEEK_SET);
	fread(dos_stub_buffer, sizeof(char), alloc_size, pe_fp);
	dos_stub_buffer[alloc_size] = 0;

	// 从后往前寻找 `Rich` 标志
	// 理论上这里的Rich headers是对齐到4字节的
	/*
	for (i = alloc_size - 4; i >= 0; i -= 4) {
		if (*(DWORD*)(dos_stub_buffer + i) == ___IMAGE_RICH_ID) {
			// 找到 `Rich`
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
			// 找到 `Rich`
			if (i + 8 >= (int)alloc_size) {
				// 处理潜在的越界读问题
				fprintf(stderr, "Detect out bound read. Bad PE file!\n");
				exit(-1);
			}
			xor_key = *(DWORD*)(dos_stub_buffer + i + 4);
			break;
		}
	}
	if (i < 0) {
		// 该PE文件可能经过修改调整，Rich headers可能被删除了
		// 也有可能该PE文件格式有误
		fprintf(stdout, "Warning: Cannot find Rich headers. (Ignore)\n");
		rich_headers.exits = false;
		return;
	}

	end = i + 8;

	// 寻找起始点
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

	// 删除首部"DanS + 3padding"和尾部"Rich + XOR key"
	if((alloc_size - 24) % 8 == 0 && (alloc_size - 24) / 8 <= 0xffff)  // 限制一下最大rich header数
		rich_headers.entries_num = (alloc_size - 24) / 8;
	else {
		fprintf(stderr, "Error: Bad PE file!\n");
		exit(-1);
	}

	// 解析头部实体
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

	// 酌情删除raw_data缓存的rich_headers原始数据
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

}

void PE32::parse_section_headers()
{

}


void PE32::print_file_info()
{

}

void PE32::print_dos_header_info()
{

	// 为了简化，我们这里只打印一些主要信息
	fprintf(stdout, "======DOS Header======\n\n");
	fprintf(stdout, "Magic number: 0x%04X\n", pe_dos_header.e_magic);
	fprintf(stdout, "File address of new exe header: 0x%X\n", pe_dos_header.e_lfanew);
	fprintf(stdout, "\n==========END=========\n\n");

}

void PE32::print_dos_stub_info()
{	

	if (!rich_headers.exits) return;

	// 打印Rich headers的信息
	fprintf(stdout, "=====Rich Headers=====\n\n");
	fprintf(stdout, "%-25s\tBuildID\t\tCount\t\tMeaning\n", "ProductName");
	for (int i = 0; i < rich_headers.entries_num; i++) {
		if (rich_headers.entries[i].r_prod_id >= __PRODID_NAME_NUM) {
			rich_headers.entries[i].r_prod_id = 0; // 非法ID？重定向到Unknow
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
	WORD temp_c, n;

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
	// 进一步解析Characteritics
	temp_c = nt_characteristics;
	n = 0;
	while (temp_c) {
		if (temp_c & 1) {
			fprintf(stdout, "    - 0x%X:\t %s\n", (1 << n), characteristics_names[n]);
		}
		temp_c = temp_c >> 1;
		n++;
	}

	// TODO

	fprintf(stdout, "\n==========END=========\n\n");
}

void PE32::print_section_headers_info()
{

}
