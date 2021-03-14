#pragma once

#include <iostream>
#include <vector>

#include "pin.H"

struct IAT_Func_entry {
	std::string Function_name;
	ADDRINT IAT_RVA;
	ADDRINT GetProcAddress_addr;
};

struct IAT_DLL_entry {
	ADDRINT LoadLibrary_addr;
	std::vector<struct IAT_Func_entry> functions;
};

typedef std::map<std::string, struct IAT_DLL_entry> IAT_table;

void IAT_add_library(IAT_table& table, char* DLL_Name, ADDRINT LoadLibrary_addr);

void IAT_add_function(IAT_table& table, char* DLL_Name, char* function_name, ADDRINT function_addr, ADDRINT GetProcAddress_addr);

void IAT_print(const IAT_table& table, std::ostream* out);

void IAT_json_save(const IAT_table& table, const std::string& path);