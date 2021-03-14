#pragma once

#include <iostream>
#include "pin.H"

void export_image(IMG img, ADDRINT OEP, const std::string& path);

void export_image_buffer(void* data, size_t size, void* ImageBase, void* RVA_OEP, const std::string& path);

