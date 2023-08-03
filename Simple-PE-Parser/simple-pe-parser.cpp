#include <iostream>
#include "pe.h"

int main()
{
    FILE* fp;
    fopen_s(&fp, "C:\\Windows\\winhlp32.exe", "rb");
    if (!fp) exit(-1);
    // 这里最好封装一个类自动区分PE32或PE32+（TODO）
    PE32* pe32_t = new PE32((char*)"winhlp32.exe", fp);
    pe32_t->print_info();
    fclose(fp);
    delete pe32_t;

    fopen_s(&fp, "C:\\Windows\\pyshellext.amd64.dll", "rb");
    if (!fp) exit(-1);
    PE64* pe64_t = new PE64((char*)"pyshellext.amd64.dll", fp);
    pe64_t->print_info();
    fclose(fp);
    delete pe64_t;

    return 0;

}
