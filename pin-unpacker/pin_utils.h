#pragma once

#include "pin.H"

SEC Find_Section(ADDRINT addr);
bool in_main_module(ADDRINT addr);
ADDRINT get_RVA(ADDRINT addr);

ADDRINT get_stack(const CONTEXT* ctx, ADDRINT offset);

IMG get_main_IMG();