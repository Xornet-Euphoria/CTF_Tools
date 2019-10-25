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


    def parse_mnemonics(self):
        raw_mnemonics = disasm(self.elf.read(self.addr, self.size),
                               arch=self.elf.arch, byte=False, offset=True).splitlines()
        for raw_m in raw_mnemonics:
            raw_m = raw_m.strip()
            re_obj = re.match(r"[0-9a-f]+:", raw_m)
            offset = int(re_obj.group()[:-1], 16)
            m_and_arg = raw_m[re_obj.end():].strip()
            mnemonic = Mnemonic(offset, m_and_arg)
            self.mnemonics.append(mnemonic)


    def dump_disas(self):
        print(disasm(self.elf.read(self.addr, self.size),
                               arch=self.elf.arch))
