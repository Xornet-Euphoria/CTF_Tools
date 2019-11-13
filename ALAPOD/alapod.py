import re
import os
import subprocess
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import Section, Symbol, SymbolTableSection
from capstone import *


class Alapod:
    def __init__(self, elf_path):
        if not os.path.isfile(elf_path):
            raise ValueError

        # formats
        self.__dump_sections_format = "{0:30} : {1:15} ~ {2:15} | {3:10} | {4:10}"
        self.__dump_functions_format = "{0:30} : {1:15} ~ {2:15} | {3:10}"
        self.__disas_function_format = "{0:15}: {1:8} {2:30}"

        self.elf_path = elf_path
        self.elf = ELFFile(open(self.elf_path, "rb"))

        self.functions_addr_dic = dict()
        self.functions_name_dic = dict()

        self.plt_got_dic = dict()
        self.got_plt_dic = dict()

        """
        self.plt_addr_dic = dict()
        self.plt_name_dic = dict()
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


    def disas_function(self, name):
        if len(self.functions_name_dic) == 0:
            self.__parse_functions()
        all_txt = self.elf.get_section_by_name(".text")
        base_addr = all_txt["sh_addr"]
        sct = self.functions_name_dic[name]
        if sct == None:
            return
        offset = sct["st_value"] - base_addr
        func_txt = all_txt.data()[offset:offset + sct["st_size"]]
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        for mnemonic in md.disasm(func_txt, sct["st_value"]):
            print(self.__disas_function_format.format(hex(mnemonic.address), mnemonic.mnemonic, mnemonic.op_str))


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
        plt_sct = self.elf.get_section_by_name(".plt")
        if plt_sct is None:
            raise ValueError
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True
        mnemonics = md.disasm(plt_sct.data(), plt_sct["sh_addr"])
        cnt = 0
        for mnemonic in mnemonics:
            if cnt % 3 == 0 and cnt != 0:
                rip = mnemonic.address + mnemonic.size
                assert len(mnemonic.operands) == 1
                rip_plus = mnemonic.operands[0].value.mem.disp
                self.plt_got_dic[mnemonic.address] = rip + rip_plus
                self.got_plt_dic[rip + rip_plus] = mnemonic.address
            cnt += 1


    def dump_plt(self):
        self.__parse_plt()
        for key, item in self.plt_got_dic.items():
            print("{}: {}".format(hex(key), hex(item)))


if __name__ == '__main__':
    alpd = Alapod("./test")
    # alpd.dump_sections()
    # alpd.dump_functions()
    # alpd.disas_function("pwnme")
    alpd.dump_plt()
    # alpd.dump_dynamic()
    # print(alpd.plt_addr_dic)
    # print(alpd.plt_name_dic)
