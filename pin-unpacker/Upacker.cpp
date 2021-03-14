#include <iostream>
#include <fstream>
#include <string.h>

#include "pin.H"
#include "utils.h" 
#include "pin_utils.h" 
#include "IAT.h"
#include "export.h"

using std::endl;

std::ostream * out = &std::cerr;

/*
    GLOBAL VARIABLES
*/

IAT_table iat_table;
char* last_LoadLibrary = NULL;

VOID save_results(ADDRINT OEP) {
    //IAT_print(iat_table, out);
    export_image(get_main_IMG(), OEP, "export.exe");
    IAT_json_save(iat_table, "IAT.json");

    exit(0); //FIXME better solution ? continue and do multiple exports (TLS) ?
}

VOID Fini(INT32 code, VOID *v)
{
    IAT_print(iat_table, out);
    *out << "DONE" << std::endl;
}

/*  Finds a function RTN object
    RTN must be closed after use
*/
RTN FindRoutine(IMG image, std::string name) {
    for (SYM sym = IMG_RegsymHead(image); SYM_Valid(sym); sym = SYM_Next(sym))
    {
        std::string fname = PIN_UndecorateSymbolName(SYM_Name(sym), UNDECORATION_NAME_ONLY);
        if (fname == name)
        {
            RTN rtn = RTN_FindByAddress(IMG_LowAddress(image) + SYM_Value(sym));
            if (RTN_Valid(rtn))
            {
                return rtn;
            }
        }
    }
    return RTN_Invalid();
}

VOID Callback_LoadLibrary(const CONTEXT* ctx, char* lib_name)
{
    ADDRINT saved_EIP = get_stack(ctx, 0);
    if (in_main_module(saved_EIP))
    {
       // *out << "Callback : LoadLibrary(" << lib_name << ") @ " << int_to_hex(saved_EIP) << endl;
        last_LoadLibrary = lib_name;
        IAT_add_library(iat_table, lib_name, get_RVA(saved_EIP));
    }
}

VOID Callback_GetProcAddress(const CONTEXT* ctx, char* funct_name)
{
    ADDRINT RBX = (ADDRINT)PIN_GetContextReg(ctx, REG_RBX);
    ADDRINT saved_EIP = get_stack(ctx, 0);
    if (in_main_module(saved_EIP))
    {
        //*out << "Callback : GetProcAddress(" << last_LoadLibrary << ", " << funct_name << ") @ " << int_to_hex(saved_EIP) << endl;
        //*out << "    RBX=" << int_to_hex(RBX) << " (" << int_to_hex(get_RVA(RBX)) << ")" << endl;
        IAT_add_function(iat_table, last_LoadLibrary, funct_name, get_RVA(RBX), get_RVA(saved_EIP)); //FIXME
    }
}

/* Called on DLL loaded by the Application */
VOID Callback_ImageLoad(IMG image, VOID* v)
{
    //*out << "Loading " << IMG_Name(image) << endl;
    RTN funct_rtn = FindRoutine(image, "LoadLibraryA");
    if (RTN_Valid(funct_rtn))
    {
        //*out << "Instrumenting LoadLibraryA in " << IMG_Name(image) << endl;
        RTN_Open(funct_rtn);
        RTN_InsertCall(funct_rtn, IPOINT_BEFORE, (AFUNPTR)Callback_LoadLibrary, IARG_CONTEXT, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
        RTN_Close(funct_rtn);
    }

    funct_rtn = FindRoutine(image, "GetProcAddress");
    if (RTN_Valid(funct_rtn))
    {
        //*out << "Instrumenting GetProcAddress in " << IMG_Name(image) << endl;
        RTN_Open(funct_rtn);
        RTN_InsertCall(funct_rtn, IPOINT_BEFORE, (AFUNPTR)Callback_GetProcAddress, IARG_CONTEXT, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_END);
        RTN_Close(funct_rtn);
    }
}

ADDRINT main_exec_section = 0;
bool last_in_exec_section = true;
ADDRINT last_ins = 0;

VOID Callback_Instruction(INS ins, VOID*) {
    // check instruction in main module
    ADDRINT ins_addr = INS_Address(ins);

    if (in_main_module(ins_addr)) { //FIXME : VirtualAlloc ?
        SEC ins_sec = Find_Section(ins_addr);
        if (!SEC_Valid(ins_sec)) {
            // should never happen inside a module !
            *out << "ERROR : instruction in main module, but not in a section ? (" << int_to_hex(ins_addr) << ")" << endl;
        }
        else {
            ADDRINT ins_secaddr = SEC_Address(ins_sec);
            if (main_exec_section == 0) {
                main_exec_section = ins_secaddr; //base section address for EntryPoint
            }
            else{
                if (main_exec_section != ins_secaddr) {
                    if (last_in_exec_section) {
                        *out << "Inter section jump found : RVA " << int_to_hex(get_RVA(ins_addr)) << " called from RVA " << int_to_hex(get_RVA(last_ins)) << endl;
                        save_results(ins_addr);
                    }
                    last_in_exec_section = false;
                }
                else {
                    last_in_exec_section = true;
                }
            }
        }
    }

    last_ins = ins_addr;
}

VOID Callback_AppStart(void* )
{
    //*out << "AppStart callback\n";
}

int main(int argc, char *argv[])
{
    // Initialize PIN library. Print help message if -h(elp) is specified
    // in the command line or the command line is invalid 
    if( PIN_Init(argc,argv) )
    {
        return 0;
    }

    PIN_InitSymbols();

    IMG_AddInstrumentFunction(Callback_ImageLoad, NULL);
    INS_AddInstrumentFunction(Callback_Instruction, NULL);

    PIN_AddApplicationStartFunction(Callback_AppStart, NULL);
    PIN_AddFiniFunction(Fini, NULL);
  
    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}