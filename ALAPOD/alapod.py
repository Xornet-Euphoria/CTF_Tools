import re
import os
from functools import reduce
import subprocess
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import Section, Symbol, SymbolTableSection
from capstone import Cs, CS_ARCH_X86, CS_MODE_64


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
        
        """
        self.plt_addr_dic = dict()
        self.plt_name_dic = dict()
        self.__parse_plt()
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
        md.detail = True
        for mnemonic in md.disasm(func_txt, sct["st_value"]):
            print(self.__disas_function_format.format(hex(mnemonic.address), mnemonic.mnemonic, mnemonic.op_str))
            regs = mnemonic.regs_access()
            read_regs = regs[0]
            write_regs = regs[1]
            
            if len(read_regs) > 1:
                print("\tRead registers: {}".format(reduce(lambda r1, r2: mnemonic.reg_name(r1) + ", " + mnemonic.reg_name(r2), read_regs)))
            elif len(read_regs) == 1:
                print("\tRead registers: {}".format(mnemonic.reg_name(read_regs[0])))
            if len(write_regs) > 1:
                print("\tWrite registers: {}".format(reduce(
                lambda r1, r2: mnemonic.reg_name(r1) + ", " + mnemonic.reg_name(r2), write_regs)))
            elif len(write_regs) == 1:
                print("\tWrite registers: {}".format(mnemonic.reg_name(write_regs[0])))

            """
            for op in mnemonic.operands:
                print(op.type)
            """


    def __parse_functions(self):
        sym_table = self.elf.get_section_by_name(".symtab")
        if not sym_table:
            raise ValueError
        for sym in sym_table.iter_symbols():
            entry = sym.entry
            if entry.st_info.type == "STT_FUNC" and entry.st_value != 0:
                self.functions_addr_dic[entry.st_value] = sym
                self.functions_name_dic[sym.name] = sym


    """
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
                # self.plt_addr_dic[addr] = name
                # self.plt_name_dic[name] = addr
    """


if __name__ == '__main__':
    alpd = Alapod("./test")
    # alpd.dump_sections()
    # alpd.dump_functions()
    alpd.disas_function("pwnme")
    # alpd.dump_dynamic()
    # print(alpd.plt_addr_dic)
    # print(alpd.plt_name_dic)
