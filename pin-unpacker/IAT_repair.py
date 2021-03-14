import argparse
import lief
import os
import json

def align(x, al):
    """ return <x> aligned to <al> """
    if x % al == 0:
        return x
    else:
        return x - (x % al) + al


def pad_data(data, al):
    """ return <data> padded with 0 to a size aligned with <al> """
    return data + ([0] * (align(len(data), al) - len(data)))


class ImportTableBuilder:

    def __init__(self, baseoffset, ptr_size):
        self.data = b""
        self.hint_name_RVA_dict = {}
        self.name_thunk_RVA_dict = {}
        self.baseoffset = baseoffset
        self.IDT_RVA = 0
        self.ptr_size = ptr_size


    def _add_name(self, name, hint=0):
        self.hint_name_RVA_dict[name] = self.baseoffset + len(self.data)
        self.data += b"\x00\x00" # hint field, added even for DLL names
        self.data += name.encode("ASCII") + b'\x00'


    def _add_thunk_list(self, dllname, name_list):
        self.name_thunk_RVA_dict[dllname] = self.baseoffset + len(self.data)
        for n in name_list:
            self._push(self.hint_name_RVA_dict[n], self.ptr_size)
        self._push(0, self.ptr_size) #end of the array


    def _add_import_descriptor(self, dllname, IAT_RVA):
        if(self.IDT_RVA ==0):
            self.IDT_RVA = self.baseoffset + len(self.data)
        self._push(self.name_thunk_RVA_dict[dllname], 4) #OriginalFirstThunk
        self._push(0, 4) #TimeDateStamp
        self._push(0, 4) #ForwarderChain
        self._push(self.hint_name_RVA_dict[dllname] + 2, 4) #DLLname, + 2 to ignore hint field
        self._push(IAT_RVA, 4) #FirstThunk


    def _push(self, val, size):
        self.data += val.to_bytes(size, "little")


    def _init_IAT(self, input_PE, base_IAT_addr, name_list):
        """
        Init the IAT to point to the functions names we created
        """
        rva = base_IAT_addr
        for n in name_list:
            data = list(self.hint_name_RVA_dict[n].to_bytes(self.ptr_size, "little"))
            input_PE.patch_address(rva, data, lief.Binary.VA_TYPES.RVA)
            rva += self.ptr_size


    def build(self, imports_names, IAT_locations, input_PE):
        """
            import_names = {
                'DLL_name':['functions_names']
            }

            IAT_locations = {'DLL_name':RVA}
        """

        for dll_name, func_names_list in imports_names.items():
            self._add_name(dll_name)  
            for fun_name in func_names_list:
                self._add_name(fun_name)

            self._add_thunk_list(dll_name, func_names_list)
            self._init_IAT(input_PE, IAT_locations[dll_name], func_names_list)

        for dll_name in imports_names.keys():
            self._add_import_descriptor(dll_name, IAT_locations[dll_name])
        self._push(0, 20) # empty import_descriptor to finish the array


if __name__ =="__main__" :

    parser = argparse.ArgumentParser(description='Pack PE binary')
    parser.add_argument('input', metavar="FILE", help='input PE file')
    parser.add_argument('iat_file', metavar="IAT FILE", help='input IAT json file')
    parser.add_argument('-o', metavar="FILE", help='output', default="IAT_corrected.exe")

    args = parser.parse_args()

    with open(args.iat_file, "r") as f:
        IAT_data = json.load(f)

    input_PE = lief.PE.parse(args.input)

    # get RVA for new section
    max_RVA = max([x.virtual_address + x.size for x in input_PE.sections])
    max_RVA = align(max_RVA, input_PE.optional_header.section_alignment)

    import_names = {}
    IAT_locations = {}

    for dll_name in IAT_data["DLL"].keys():
        import_names[dll_name] = []
        IAT_locations[dll_name] = 0

        func_dict = IAT_data["DLL"][dll_name]["functions"]

        for fun_name in func_dict.keys():
            import_names[dll_name] += [fun_name]

        IAT_loc = min([int(infos["IAT_RVA"], 16) for (name, infos) in func_dict.items()])

        IAT_locations[dll_name] = IAT_loc

    builder = ImportTableBuilder(max_RVA, 8)

    builder.build(import_names, IAT_locations, input_PE)

    import_data = pad_data(list(builder.data), input_PE.optional_header.file_alignment)
    import_section = lief.PE.Section(name=".imp")
    import_section.content = import_data
    import_section.size = len(import_data)
    import_section.virtual_address = max_RVA
    import_section.characteristics = (lief.PE.SECTION_CHARACTERISTICS.MEM_READ
                                        | lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE)

    input_PE.add_section(import_section)

    # change the file ehaders

    # make lief compute the new sizeof_image
    input_PE.optional_header.sizeof_image = 0

    # chagne the Import table to point to ours
    import_data_dir = input_PE.data_directory(lief.PE.DATA_DIRECTORY.IMPORT_TABLE)
    import_data_dir.rva = builder.IDT_RVA
    import_data_dir.size = len(builder.data)

    # not supposed to move (no reloctions table)
    input_PE.optional_header.dll_characteristics = 0

    # make all sections writable (make sur the IAT is writable)
    for s in input_PE.sections:
        s.characteristics = s.characteristics | lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE


    # save the resulting PE
    if(os.path.exists(args.o)):
        # little trick here : lief emits no warning when it cannot write because the output
        # file is already opened. Using this function ensure we fail in this case (avoid errors).
        os.remove(args.o)

    builder = lief.PE.Builder(input_PE)
    builder.build()
    builder.write(args.o)

    print(f"Output saved in {args.o}")





