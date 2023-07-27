#pragma once
#include "winntdef.h"

typedef struct __RICH_HEADER_DATA {
	int   data_size;
	char* data_ptr;
}RICH_HEADER_DATA;

typedef struct __RICH_HEADER_ENTRY {
	// Build ID
	// Product ID
	// Count
	WORD  r_build_id;
	WORD  r_prod_id;
	DWORD r_count;

}RICH_HEADER_ENTRY, *PRICH_HEADER_ENTRY;

typedef struct __RICH_HEADER {
	RICH_HEADER_DATA   raw_data;
	PRICH_HEADER_ENTRY entries;  // pointer
	int                entries_size;
	bool			   exits;
}RICH_HEADER, * PRICH_HEADER;