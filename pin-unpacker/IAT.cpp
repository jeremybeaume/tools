#include <iostream>
#include <fstream>

#include "IAT.h"
#include "utils.h"

using std::endl;

void IAT_add_library(IAT_table& table, char* DLL_Name, ADDRINT LoadLibrary_addr)
{
	struct IAT_DLL_entry& funct_entry = table[std::string(DLL_Name)];
	if (funct_entry.LoadLibrary_addr != 0) {
		funct_entry.LoadLibrary_addr = LoadLibrary_addr;
	}
}

void IAT_add_function(IAT_table& table, char* DLL_Name, char* function_name, ADDRINT function_addr, ADDRINT GetProcAddress_addr)
{
	struct IAT_Func_entry entry;
	entry.Function_name = std::string(function_name);
	entry.IAT_RVA = function_addr;
	entry.GetProcAddress_addr = GetProcAddress_addr;

	struct IAT_DLL_entry& funct_entry = table[std::string(DLL_Name)];
	funct_entry.functions.push_back(entry);
}

void IAT_print(const IAT_table& table, std::ostream* out)
{
	*out << "=== IAT ===" << endl;
	for (std::pair<std::string, struct IAT_DLL_entry> element : table)
	{
		*out << element.first << " (Loaded @ " << int_to_hex(element.second.LoadLibrary_addr) << ")" << endl;
		for (struct IAT_Func_entry entry : element.second.functions)
		{
			*out << "    " << entry.Function_name << " @ " << int_to_hex(entry.IAT_RVA) << " (Loaded @ " << int_to_hex(entry.GetProcAddress_addr) << ")" << endl;
		}
	}
}

void IAT_json_save(const IAT_table& table, const std::string& path)
{
	std::ofstream outFile;
	outFile.open(path.c_str());

	outFile << "{\n  \"DLL\":{\n";

	bool first_DLL = true;
	for (std::pair<std::string, struct IAT_DLL_entry> element : table)
	{
		if (!first_DLL) {
			outFile << ",\n";
		}
		first_DLL = false;
		outFile << "    \"" << element.first << "\":{\n";
		outFile << "      \"LoadLibrary_RVA\":\"" << int_to_hex(element.second.LoadLibrary_addr) << "\",\n";
		outFile << "      \"functions\":{\n";

		bool first_function = true;
		for (struct IAT_Func_entry entry : element.second.functions)
		{
			if (!first_function) {
				outFile << ",\n";
			}
			first_function = false;
			outFile << "        \"" << entry.Function_name << "\":{\n";
			outFile << "          \"IAT_RVA\":\"" << int_to_hex(entry.IAT_RVA) <<"\",\n";
			outFile << "          \"GetProcAddress_RVA\":\"" << int_to_hex(entry.GetProcAddress_addr) << "\"\n";
			outFile << "        }";
		}
		outFile << "\n      }\n";
		outFile << "    }";
	}
	outFile << "\n  }\n}\n";

	outFile.close();
	std::cerr << "IAT saved in " << path << endl;
}