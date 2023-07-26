#include <iostream>
#include "pe-init.h"

int main()
{
    FILE* fp;
    fopen_s(&fp, "C:\\Users\\lenovo\\Desktop\\hello_world.exe", "r");
    std::cout << pe_validate(fp) << '\n';

}
