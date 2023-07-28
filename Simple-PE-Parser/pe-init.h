#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "winntdef.h"

// 用于验证PE文件的合法性
int pe_validate(FILE* file);
