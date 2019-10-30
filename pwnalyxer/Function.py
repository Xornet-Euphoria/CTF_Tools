from pwn import ELF, asm, disasm
import re
from Mnemonic import Mnemonic 


# todo: 関数の中身の解析(ローカル変数の数やできるなら初期値も調べたい)
class Function:
    def __init__(self, f, elf):
        self.elf = elf
        self.addr = f.address
        self.name = f.name
        self.size = f.size
        self.mnemonics = []


    def parse_mnemonics(self, detail=False):
        raw_mnemonics = disasm(self.elf.read(self.addr, self.size),
                               arch=self.elf.arch, byte=False, offset=True).splitlines()
        for raw_m in raw_mnemonics:
            raw_m = raw_m.strip()
            re_obj = re.match(r"[0-9a-f]+:", raw_m)
            offset = int(re_obj.group()[:-1], 16)
            m = raw_m[re_obj.end():].strip()
            mnemonic = Mnemonic(self.addr + offset, m, detail)
            self.mnemonics.append(mnemonic)


    def dump_disas(self, detail=False):
        if detail:
            self.parse_mnemonics(detail)
            for m in self.mnemonics:
                operands = m.operands
                s_operands = ""
                for op in operands:
                    if s_operands != "":
                        s_operands += ", "
                    s_operands += op
                print("{0:15}: {1:8} {2}  {3}".format(hex(m.addr), m.opecode, s_operands, m.comment))
        else:
            print(disasm(self.elf.read(self.addr, self.size),
                               arch=self.elf.arch))
