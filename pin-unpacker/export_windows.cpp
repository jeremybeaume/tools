/*
	Functions of export.h that needs Windows.h included
	windows.h and pin.H cannot be included simultaneously
*/

#include <iostream>
#include <string>

#include <windows.h>
#include <winnt.h>


//#include "export.h" // this one includes pin, do NOT IMPORT
#include "utils.h"

using std::endl;

size_t pad_size(size_t data, size_t align)
{
	if (data % align == 0) {
		return 0;
	}
	else {
		return align - (data % align);
	}
}

size_t align(size_t data, size_t align)
{
	return data + pad_size(data, align);
}

/*
	Saves the sections of a IMG object to a file
*/
void export_image_buffer(void* data, size_t size, void* ImageBase, void* RVA_OEP, const std::string& path)
{
	IMAGE_DOS_HEADER* p_DOS_HDR = (IMAGE_DOS_HEADER*) data;
	IMAGE_NT_HEADERS* p_NT_HDR = (IMAGE_NT_HEADERS*)(((char*)p_DOS_HDR) + p_DOS_HDR->e_lfanew);
	IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*)(p_NT_HDR + 1);
	
	//Change Optional Header, disable int size warnings
	#pragma warning(suppress: 4311)
	#pragma warning(suppress: 4302)
	p_NT_HDR->OptionalHeader.ImageBase = (ULONGLONG) ImageBase; // #FIXME : 64 bits ....
	
	#pragma warning(suppress: 4311)
	#pragma warning(suppress: 4302)
	p_NT_HDR->OptionalHeader.AddressOfEntryPoint = (DWORD) RVA_OEP;

	//Change sections :
	//	all sections have RawSize = VirtualSize
	//  and RawAddress = VirtualAddress

	for (int i = 0; i < p_NT_HDR->FileHeader.NumberOfSections; ++i) {
		sections[i].SizeOfRawData = sections[i].Misc.VirtualSize;
		sections[i].PointerToRawData = sections[i].VirtualAddress;
	}

	// Save the result

	FILE* file = fopen(path.c_str(), "wb");
	if (!file) {
		std::cerr << "ERROR opening output file " << int_to_hex(GetLastError()) << endl;
		return;
	}

	fwrite(data, size, 1, file);

	fclose(file);
}