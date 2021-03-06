"""
Replace immediate values push before a call by enum value
"""

from idc import *
from idaapi import *
from idautils import *
from ida_enum import *

def replace_pushed_int(function_ea, target_push_n, target_enum_name, before_limit=0x30, int_type="hex"):
    """
    Replace the <target_push_n> last immediate value push before by enum value if possible

    function_ea : target function ea (will check Xref to this ea)
                  for structs use get_name_ea_simple
    target_push_n : how many push back we want, starts at 1
    target_enum_name : enum to target (created if doesn't exists)
    before_limit : how much back we agree to go
    str_type : "hex" or "dec", used for the enum value names (in hex or dec number)
    """

    target_enum = get_enum(target_enum_name)
    if target_enum == BADADDR:
        if int_type == "hex":
            target_enum = add_enum(0, target_enum_name, hex_flag())
        else:
            target_enum = add_enum(0, target_enum_name, dec_flag())

    for xref in XrefsTo(function_ea, 0):
        current_ea = xref.frm
        push_n = 0
        
        while current_ea != BADADDR:
            current_ea = prev_head(current_ea, xref.frm - before_limit)
            
            if print_insn_mnem(current_ea) == "push":
                push_n += 1

                if push_n == target_push_n: # that's the push we are looking for

                    type_n = get_operand_type(current_ea, 0)
                    if type_n == 5: # immediate value
                        value = get_operand_value(current_ea, 0)
                       
                        enum_value = get_enum_member(target_enum, value, 0, 0)
                        if enum_value == BADADDR:
                            # Create a new enum value
                            if int_type == "hex":
                                enum_val_name = "{:02X}".format(value)
                            else:
                                enum_val_name = str(value)

                            enum_value = add_enum_member(target_enum, get_enum_name(target_enum) + "_" + enum_val_name, value)

                        op_enum(current_ea, 0, target_enum, 0)

                    else: # not an immediate value
                        print(f"Help needed @ {hex(current_ea)}")
                    
                    break # Done here, break to the next Xref
