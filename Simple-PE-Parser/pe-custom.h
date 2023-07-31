#pragma once
#include "winntdef.h"

#define __PRODID_NAME_NUM 0x010f

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
	int                entries_num;
	bool			   exits;
}RICH_HEADER, * PRICH_HEADER;

/* 
 *  Copy from
 *  https://github.com/hasherezade/bearparser/blob/65d6417b1283eb64237141ee0c865bdf0f13ac73/parser/pe/RichHdrWrapper.cpp
 */
static const char* prod_ids_to_names[__PRODID_NAME_NUM] = {
	"Unknown", "Import0", "Linker510", "Cvtomf510",
	"Linker600", "Cvtomf600", "Cvtres500", "Utc11_Basic",
	"Utc11_C", "Utc12_Basic", "Utc12_C", "Utc12_CPP",
	"AliasObj60", "VisualBasic60", "Masm613", "Masm710",
	"Linker511", "Cvtomf511", "Masm614", "Linker512",
	"Cvtomf512", "Utc12_C_Std", "Utc12_CPP_Std",
	"Utc12_C_Book", "Utc12_CPP_Book", "Implib700",
	"Cvtomf700", "Utc13_Basic", "Utc13_C", "Utc13_CPP",
	"Linker610", "Cvtomf610", "Linker601", "Cvtomf601",
	"Utc12_1_Basic", "Utc12_1_C", "Utc12_1_CPP", "Linker620",
	"Cvtomf620", "AliasObj70", "Linker621", "Cvtomf621",
	"Masm615", "Utc13_LTCG_C", "Utc13_LTCG_CPP", "Masm620",
	"ILAsm100", "Utc12_2_Basic", "Utc12_2_C", "Utc12_2_CPP",
	"Utc12_2_C_Std", "Utc12_2_CPP_Std", "Utc12_2_C_Book",
	"Utc12_2_CPP_Book", "Implib622", "Cvtomf622", "Cvtres501",
	"Utc13_C_Std", "Utc13_CPP_Std", "Cvtpgd1300", "Linker622",
	"Linker700", "Export622", "Export700", "Masm700",
	"Utc13_POGO_I_C", "Utc13_POGO_I_CPP", "Utc13_POGO_O_C",
	"Utc13_POGO_O_CPP", "Cvtres700", "Cvtres710p",
	"Linker710p", "Cvtomf710p", "Export710p", "Implib710p",
	"Masm710p", "Utc1310p_C", "Utc1310p_CPP", "Utc1310p_C_Std",
	"Utc1310p_CPP_Std", "Utc1310p_LTCG_C", "Utc1310p_LTCG_CPP",
	"Utc1310p_POGO_I_C", "Utc1310p_POGO_I_CPP", "Utc1310p_POGO_O_C",
	"Utc1310p_POGO_O_CPP", "Linker624", "Cvtomf624",
	"Export624", "Implib624", "Linker710", "Cvtomf710",
	"Export710", "Implib710", "Cvtres710", "Utc1310_C",
	"Utc1310_CPP", "Utc1310_C_Std", "Utc1310_CPP_Std",
	"Utc1310_LTCG_C", "Utc1310_LTCG_CPP", "Utc1310_POGO_I_C",
	"Utc1310_POGO_I_CPP", "Utc1310_POGO_O_C", "Utc1310_POGO_O_CPP",
	"AliasObj710", "AliasObj710p", "Cvtpgd1310", "Cvtpgd1310p",
	"Utc1400_C", "Utc1400_CPP", "Utc1400_C_Std", "Utc1400_CPP_Std",
	"Utc1400_LTCG_C", "Utc1400_LTCG_CPP", "Utc1400_POGO_I_C",
	"Utc1400_POGO_I_CPP", "Utc1400_POGO_O_C", "Utc1400_POGO_O_CPP",
	"Cvtpgd1400", "Linker800", "Cvtomf800", "Export800", "Implib800",
	"Cvtres800", "Masm800", "AliasObj800", "PhoenixPrerelease",
	"Utc1400_CVTCIL_C", "Utc1400_CVTCIL_CPP", "Utc1400_LTCG_MSIL",
	"Utc1500_C", "Utc1500_CPP", "Utc1500_C_Std", "Utc1500_CPP_Std",
	"Utc1500_CVTCIL_C", "Utc1500_CVTCIL_CPP", "Utc1500_LTCG_C",
	"Utc1500_LTCG_CPP", "Utc1500_LTCG_MSIL", "Utc1500_POGO_I_C",
	"Utc1500_POGO_I_CPP", "Utc1500_POGO_O_C", "Utc1500_POGO_O_CPP",
	"Cvtpgd1500", "Linker900", "Export900", "Implib900", "Cvtres900",
	"Masm900", "AliasObj900", "Resource", "AliasObj1000",
	"Cvtpgd1600", "Cvtres1000", "Export1000", "Implib1000",
	"Linker1000", "Masm1000", "Phx1600_C", "Phx1600_CPP",
	"Phx1600_CVTCIL_C", "Phx1600_CVTCIL_CPP", "Phx1600_LTCG_C",
	"Phx1600_LTCG_CPP", "Phx1600_LTCG_MSIL", "Phx1600_POGO_I_C",
	"Phx1600_POGO_I_CPP", "Phx1600_POGO_O_C", "Phx1600_POGO_O_CPP",
	"Utc1600_C", "Utc1600_CPP", "Utc1600_CVTCIL_C",
	"Utc1600_CVTCIL_CPP", "Utc1600_LTCG_C", "Utc1600_LTCG_CPP",
	"Utc1600_LTCG_MSIL", "Utc1600_POGO_I_C", "Utc1600_POGO_I_CPP",
	"Utc1600_POGO_O_C", "Utc1600_POGO_O_CPP", "AliasObj1010",
	"Cvtpgd1610", "Cvtres1010", "Export1010", "Implib1010",
	"Linker1010", "Masm1010", "Utc1610_C", "Utc1610_CPP",
	"Utc1610_CVTCIL_C", "Utc1610_CVTCIL_CPP", "Utc1610_LTCG_C",
	"Utc1610_LTCG_CPP", "Utc1610_LTCG_MSIL", "Utc1610_POGO_I_C",
	"Utc1610_POGO_I_CPP", "Utc1610_POGO_O_C", "Utc1610_POGO_O_CPP",
	"AliasObj1100", "Cvtpgd1700", "Cvtres1100", "Export1100",
	"Implib1100", "Linker1100", "Masm1100", "Utc1700_C",
	"Utc1700_CPP", "Utc1700_CVTCIL_C", "Utc1700_CVTCIL_CPP",
	"Utc1700_LTCG_C", "Utc1700_LTCG_CPP", "Utc1700_LTCG_MSIL",
	"Utc1700_POGO_I_C", "Utc1700_POGO_I_CPP", "Utc1700_POGO_O_C",
	"Utc1700_POGO_O_CPP", "AliasObj1200", "Cvtpgd1800", "Cvtres1200",
	"Export1200", "Implib1200", "Linker1200", "Masm1200",
	"Utc1800_C", "Utc1800_CPP", "Utc1800_CVTCIL_C", "Utc1800_CVTCIL_CPP",
	"Utc1800_LTCG_C", "Utc1800_LTCG_CPP", "Utc1800_LTCG_MSIL",
	"Utc1800_POGO_I_C", "Utc1800_POGO_I_CPP", "Utc1800_POGO_O_C",
	"Utc1800_POGO_O_CPP", "AliasObj1210", "Cvtpgd1810", "Cvtres1210",
	"Export1210", "Implib1210", "Linker1210", "Masm1210", "Utc1810_C",
	"Utc1810_CPP", "Utc1810_CVTCIL_C", "Utc1810_CVTCIL_CPP",
	"Utc1810_LTCG_C", "Utc1810_LTCG_CPP", "Utc1810_LTCG_MSIL",
	"Utc1810_POGO_I_C", "Utc1810_POGO_I_CPP", "Utc1810_POGO_O_C",
	"Utc1810_POGO_O_CPP", "AliasObj1400", "Cvtpgd1900", "Cvtres1400",
	"Export1400", "Implib1400", "Linker1400", "Masm1400", "Utc1900_C",
	"Utc1900_CPP", "Utc1900_CVTCIL_C", "Utc1900_CVTCIL_CPP", "Utc1900_LTCG_C",
	"Utc1900_LTCG_CPP", "Utc1900_LTCG_MSIL","Utc1900_POGO_I_C",
	"Utc1900_POGO_I_CPP", "Utc1900_POGO_O_C", "Utc1900_POGO_O_CPP"
};

static const char* translate_machine(WORD w) {
	switch (w) {
		case 0x014C:
			return "x86";
		case 0x8664:
			return "x64";
		case 0x0200:
			return "Intel Itanium";
		default:
			return "Unknow";
	}
}

/* 
 *  https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#characteristics
*/
static const char* characteristics_names[] = {
	"Relocation info stripped from file.",
	"File is executable  (i.e. no unresolved external references).",
	"Line numbers stripped from file.",
	"Local symbols stripped from file.",
	"Aggressively trim working set.",
	"App can handle > 2gb addresses.",
	" * Reserved",
	"Bytes of machine word are reversed.",
	"32 bit word machine.",
	"Debugging info stripped from file in .DBG file.",
	"If Image is on removable media, copy and run from the swap file.",
	"If Image is on Net, copy and run from the swap file.",
	"System File.",
	"File is a DLL.",
	"File should only be run on a UP machine.",
	"Bytes of machine word are reversed."
};

static const char* translate_nt_optional_header_magic(WORD w) {
	switch (w) {
		case 0x010B:
			return "NT32";
		case 0x020B:
			return "NT64";
		case 0x0107:
			return "ROM";
		default:
			return "Unknown";
	}
}

static const char* translate_data_directory(int idx) {

	switch (idx) {
		case ___IMAGE_DIRECTORY_ENTRY_EXPORT:
			return "Export Directory";
		case ___IMAGE_DIRECTORY_ENTRY_IMPORT:
			return "Import Directory";
		case ___IMAGE_DIRECTORY_ENTRY_RESOURCE:
			return "Resource Directory";
		case ___IMAGE_DIRECTORY_ENTRY_EXCEPTION:
			return "Exception Directory";
		case ___IMAGE_DIRECTORY_ENTRY_SECURITY:
			return "Security Directory";
		case ___IMAGE_DIRECTORY_ENTRY_BASERELOC:
			return "Base Relocation Table";
		case ___IMAGE_DIRECTORY_ENTRY_DEBUG:
			return "Debug Directory";
		case ___IMAGE_DIRECTORY_ENTRY_ARCHITECTURE:
			return "Architecture Specific Data";
		case ___IMAGE_DIRECTORY_ENTRY_GLOBALPTR:
			return "RVA of GlobalPtr";
		case ___IMAGE_DIRECTORY_ENTRY_TLS:
			return "TLS Directory";
		case ___IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG:
			return "Load Configuration Directory";
		case ___IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT:
			return "Bound Import Directory";
		case ___IMAGE_DIRECTORY_ENTRY_IAT:
			return "Import Address Table";
		case ___IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT:
			return "Delay Load Import Descriptors";
		case ___IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR:
			return ".NET header";
		default:
			return "Unknown";
	}

}