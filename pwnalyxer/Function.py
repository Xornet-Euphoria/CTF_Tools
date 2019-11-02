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
        self.call_addresses = []


    def parse_mnemonics(self, detail=False):
        raw_mnemonics = disasm(self.elf.read(self.addr, self.size),
                               arch=self.elf.arch, byte=True, offset=True).splitlines()
        for raw_m in raw_mnemonics:
            raw_m = raw_m.strip()
            re_obj = re.match(r"[0-9a-f]+:", raw_m)
            offset = int(re_obj.group()[:-1], 16)
            bytes_and_m = raw_m[re_obj.end():].strip()
            re_obj = re.match(r"([0-9a-f][0-9a-f] )+ ", bytes_and_m)
            s_bytes = re_obj.group().strip().split(" ")
            m_bytes = list(map(lambda x: int(x, 16), s_bytes))
            m = bytes_and_m[re_obj.end():].strip()
            mnemonic = Mnemonic(self.addr + offset, m, detail, byte_list=m_bytes)
            self.mnemonics.append(mnemonic)

    
    def analyze_function(self):
        # ニーモニック解析
        self.parse_mnemonics(True)
        # 関数内解析
        # シンボル辞書逆転
        func_addr_dict = {v.address: k for k, v in self.elf.functions.items()}
        plt_addr_dict = {v: k for k, v in self.elf.plt.items()}

        # 自身が呼ぶシンボル一覧
        for m in self.mnemonics:
            if m.opecode == "call":
                called_addr = m.operands[0]["value"]
                self.call_addresses.append(called_addr)
                if called_addr in func_addr_dict:
                    symbol_name = func_addr_dict[called_addr]
                elif called_addr in plt_addr_dict:
                    symbol_name = "{}@plt".format(plt_addr_dict[called_addr])
                else:
                    symbol_name = "unknown"

                m.raw_operands[0] += " ({})".format(symbol_name)


        # todo: ローカル変数検出


    def dump_disas(self, detail=False):
        if detail:
            print("{0:15}: {1:8} {2}".format(
                "address", "opecode", "operands & comment"))
            print("-" * 60)
            self.analyze_function()

            # dump
            for m in self.mnemonics:
                operands = m.raw_operands
                s_operands = ""
                s_types = ""
                for op in operands:
                    if s_operands != "":
                        s_operands += ", "
                    s_operands += op

                if len(m.operands) != 0:
                    s_types = "# types: "
                    for i, op in enumerate(m.operands):
                        if i != 0:
                            s_types += ", "
                        s_types += op["type"]
                
                print("{0:15}: {1:8} {2:30}  {3:15} {4}".format(hex(m.addr), m.opecode, s_operands, s_types, m.comment))
        else:
            print(disasm(self.elf.read(self.addr, self.size),
                               arch=self.elf.arch))
