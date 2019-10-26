from pwn import ELF
from Function import Function


class Functions:
    def __init__(self, elf):
        self.functions = []
        self.name_dict = dict()
        self.__table_header = "{0:30} : {1:15} ~ {2:15} | {3:10}"
        for func in elf.functions.values():
            f = Function(func, elf)
            self.functions.append(f)
            self.name_dict[f.name] = f


    def __make_table_header(self):
        print(self.__table_header.format("function name", "start address", "end address", "size"))
        print("-" * 80)


    def dump_functions(self, functions):
        self.__make_table_header()
        for function in functions:
            print(self.__table_header.format(function.name, hex(function.addr), hex(function.addr + function.size - 1), function.size))

    
    def dump_all_functions(self):
        self.dump_functions(self.functions)


    def search_function_by_name(self, func_name):
        if func_name in self.name_dict.keys():
            return self.name_dict[func_name]

        return None
