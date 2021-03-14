#include <iostream>

#include "pin_utils.h"
#include "utils.h"

using std::endl;

SEC Find_Section(ADDRINT addr)
{
    //List images loaded in memory
    IMG img = IMG_FindByAddress(addr);
    if (IMG_Valid(img))
    {
        for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
        {
            ADDRINT sec_addr = SEC_Address(sec);
            USIZE sec_size = SEC_Size(sec);
            if (addr >= sec_addr && addr <= sec_addr + sec_size)
            {
                return sec;
            }
        }
    }
    return SEC_Invalid();
}

bool in_main_module(ADDRINT addr)
{
    PIN_LockClient();
    IMG img = IMG_FindByAddress(addr);
    PIN_UnlockClient();

    if (!IMG_Valid(img))
    {
        return false;
    }
    return IMG_IsMainExecutable(img);
}

ADDRINT get_RVA(ADDRINT addr)
{
    PIN_LockClient();
    IMG img = IMG_FindByAddress(addr);
    PIN_UnlockClient();

    if (!IMG_Valid(img))
    {
        std::cerr << "WARNING : No module found for address " << int_to_hex(addr) << endl;
        return addr;
    }
    return addr - IMG_LowAddress(img);
}

ADDRINT get_stack(const CONTEXT* ctx, ADDRINT offset)
{
    ADDRINT RSP = (ADDRINT)PIN_GetContextReg(ctx, REG_STACK_PTR);
    ADDRINT data;
    PIN_SafeCopy(&data, (void*)(RSP + offset), sizeof(ADDRINT));
    return data;
}

void print_call_stack(const CONTEXT* ctx, std::ostream* out) {
    ADDRINT RBP = (ADDRINT)PIN_GetContextReg(ctx, REG_RBP);
    ADDRINT EIP_saved;
    while (RBP != 0) {
        PIN_SafeCopy(&EIP_saved, (void*)(RBP + sizeof(ADDRINT)), sizeof(ADDRINT));
        *out << " " << int_to_hex(EIP_saved) << endl;
        PIN_SafeCopy(&RBP, (void*)(RBP), sizeof(ADDRINT));
    }
}

static IMG _main_img = IMG_Invalid();

IMG get_main_IMG()
{
    if (IMG_Valid(_main_img)) {
        return _main_img;
    }
    else {
        for (IMG img = APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img)) {
            if (IMG_IsMainExecutable(img)) {
                _main_img = img;
                return _main_img;
            }
        }
    }
    return IMG_Invalid();

}