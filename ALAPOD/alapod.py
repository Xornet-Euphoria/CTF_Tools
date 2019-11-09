import re
import os
import subprocess
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import Section, Symbol, SymbolTableSection


class Alapod:
    def __init__(self, elf_path):
        if not os.path.isfile(elf_path):
            raise ValueError

        # formats
        self.__dump_sections_format = "{0:30} : {1:15} ~ {2:15} | {3:10} | {4:10}"
        self.__dump_functions_format = "{0:30} : {1:15} ~ {2:15} | {3:10}"

        self.elf_path = elf_path
        self.elf = ELFFile(open(self.elf_path, "rb"))

        self.functions_addr_dic = dict()
        self.functions_name_dic = dict()
        
        """
        self.plt_addr_dic = dict()
        self.plt_name_dic = dict()
        self.__parse_plt()

        self.text_addr_dic = dict()
        self.text_name_dic = dict()
        self.__parse_text()
        """


    # dump
    def dump_sections(self):
        for sct in self.elf.iter_sections():
            if sct.name == "":
                continue
            header = sct.header
            addr = header.sh_addr
            size = header.sh_size
            is_writable = "yes" if (header.sh_flags % 2 == 1) else "no"
            end = addr + size - 1 if size != 0 else 0
            print(self.__dump_sections_format.format(sct.name, hex(
                addr), hex(end), size, is_writable))


    def dump_functions(self):
        if len(self.functions_addr_dic) == 0:
            self.__parse_functions()
        for name in self.functions_name_dic.keys():
            entry = self.functions_name_dic[name].entry
            addr = entry.st_value
            size = entry.st_size
            if size > 0:
                print(self.__dump_functions_format.format(name, hex(addr), hex(addr + size - 1), size))


    def dump_dynamic(self):
        dyn = self.elf.get_section_by_name(".dynamic")
        if not dyn:
            raise ValueError
        
        for tag in dyn.iter_tags():
            print(tag)


    def __parse_functions(self):
        sym_table = self.elf.get_section_by_name(".symtab")
        if not sym_table:
            raise ValueError
        for sym in sym_table.iter_symbols():
            entry = sym.entry
            if entry.st_info.type == "STT_FUNC" and entry.st_value != 0:
                self.functions_addr_dic[entry.st_value] = sym
                self.functions_name_dic[sym.name] = sym


    def __parse_plt(self):
        # parsing .plt section
        command = ["objdump", "-M", "intel", "-j", ".plt", "-d", self.elf_path]
        res = subprocess.run(command, capture_output=True)
        out = res.stdout.decode()
        out_lines = out.split("\n")
        for line in out_lines:
            if re.match(r"[0-9a-f]+ <.+plt>", line):
                parsed_line = line.split(" ")
                addr = int(parsed_line[0], 16)
                name = parsed_line[1]
                black_list = ["<", "@", "plt>:"]
                for b_s in black_list:
                    name = name.replace(b_s, "")
                self.plt_addr_dic[addr] = name
                self.plt_name_dic[name] = addr


    def __parse_text(self):
        command = ["objdump", "-M", "intel", "-j", ".text", "-d", self.elf_path]
        res = subprocess.run(command, capture_output=True)
        out = res.stdout.decode()
        out_lines = out.split("\n")
        for line in out_lines:
            if re.match(r"[0-9a-f]+ <.+>:", line):
                parsed_line = line.split(" ")
                addr = int(parsed_line[0], 16)
                name = parsed_line[1]
                black_list = ["<", ">:"]
                for b_s in black_list:
                    name = name.replace(b_s, "")
                self.text_addr_dic[addr] = name
                self.text_name_dic[name] = addr


    def symbol_parse(self, symbol):
        pass

        """
        command = ["objdump", "-M", "intel", "-d", self.elf_path]
        res = subprocess.run(command, capture_output=True)
        out = res.stdout.decode()
        print(out)
        """


if __name__ == '__main__':
    alpd = Alapod("./test")
    # alpd.dump_sections()
    alpd.dump_functions()
    # alpd.dump_dynamic()
    # print(alpd.plt_addr_dic)
    # print(alpd.plt_name_dic)
    # print(alpd.text_addr_dic)
    # print(alpd.text_name_dic)
