#include <iostream>
#include <strings.h>

using std::endl;

std::string int_to_hex(ADDRINT val)
{
    char buff[33];
    sprintf(buff, "0x%llx", val);
    return std::string(buff);
}
