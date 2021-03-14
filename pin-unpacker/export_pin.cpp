/*
	Pin side for the exports
	windows.h and pin.H cannot be included simultaneously
*/

#include <iostream>
#include <string>

#include "pin.H"

#include "export.h"
#include "utils.h"

using std::endl;

void export_image(IMG img, ADDRINT OEP, const std::string& path) {
	size_t size = IMG_HighAddress(img) - IMG_LowAddress(img) + 1;
	char* buffer = (char*) malloc(size);

	PIN_SafeCopy(buffer, (void*) IMG_LowAddress(img), size);

	export_image_buffer(buffer, size, (void*)IMG_LowAddress(img), (void*) (OEP - IMG_LowAddress(img)), path);

	free(buffer);

	std::cerr << "Module " << IMG_Name(img) << " saved at " << path << endl;
}