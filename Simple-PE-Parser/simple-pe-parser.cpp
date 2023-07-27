#include <iostream>
#include "pe-init.h"
#include "pe32.h"

int main()
{
    FILE* fp;
    fopen_s(&fp, "C:\\Users\\lenovo\\Desktop\\test32.exe", "r");
    PE32* pe32_t = new PE32((char*)"test32.exe", fp);
    pe32_t->print_info();
    return 0;

}
