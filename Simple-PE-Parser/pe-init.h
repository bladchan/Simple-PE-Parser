#pragma once
#include <stdio.h>
#include "pe32.h"
#include "pe-custom.h"
#include "winntdef.h"

// 用于验证PE文件的合法性
int pe_validate(FILE* file);
