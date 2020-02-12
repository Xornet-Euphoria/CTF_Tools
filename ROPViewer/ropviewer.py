from test_functions import *
from pwn import ELF
from capstone import Cs, CS_ARCH_X86, CS_MODE_64


class RopViewer:
    def __init__(self, elf_path, payload, base_addr=None):
        self.elf = ELF(elf_path)
        
        if self.elf.pie and base_addr is None:
            print("[+]: PIE is enabled")
            self.addr = base_addr
            exit()
        else:
            self.addr = self.elf.address
        self.payload = payload
        
        self.text = self.elf.get_section_by_name(".text")
        if self.text is None:
            # todo: error handling
            print("[+]: where is text section???")
            exit()

        self.dumper = HexDumper(self.payload, self.elf.bits // 8)
        self._external_dict = {}

        mode = CS_MODE_64 if self.elf.bits == 64 else CS_MODE_32
        md = Cs(CS_ARCH_X86, mode)
        self.mnemonics = {}

        for mnemonic in md.disasm(self.text.data(), self.text.header.sh_addr):
            self.mnemonics[mnemonic.address] = mnemonic


    @property
    def external_dict(self):
        pass

    @external_dict.setter
    def external_dict(self, d):
        self._external_dict = d


    def add_dict(self, key, value):
        self._external_dict[key] = value


    def merge_dict(self, d):
        self._external_dict.update(d)


    def dump(self):
        max_addr = self.dumper.data[-1].addr
        max_byte_length = max_addr.bit_length() // 4 + 1

        fmt_not_rop = f"{{:{max_byte_length}x}}: {{}} -> {{:16x}} | [unknown]"
        fmt_rop = f"{{:{max_byte_length}x}}: {{}} -> {{:16x}} | [{{}}]: {{}}"

        for hd in self.dumper.data:
            if self.__in_text(hd.value):
                if hd.value in self.mnemonics.keys():
                    print(fmt_rop.format(hd.addr, hd.dump_string, hd.value, "gadget", self.__get_full_gadget_str(self.mnemonics[hd.value])))
                else:
                    print(fmt_rop.format(hd.addr, hd.dump_string, hd.value, "unknown gadget", "???"))

            elif hd.value in self._external_dict.keys():
                print(fmt_rop.format(hd.addr, hd.dump_string, hd.value, "value", self._external_dict[hd.value]))
            elif self.__analyze_pop(hd)["is_poped"]:
                desc = "({})".format(self.__analyze_pop(hd)["register"])
                
                print(fmt_rop.format(hd.addr, hd.dump_string, hd.value, "poped", desc))
            else:
                print(fmt_not_rop.format(hd.addr, hd.dump_string, hd.value))


    def __in_text(self, addr):
        start = self.text.header.sh_addr
        end = start + self.text.header.sh_size
        return addr >= start and addr < end


    def __str_mnemonic(self, mnemonic):
        s = mnemonic.mnemonic
        s += " "
        s += mnemonic.op_str

        return s


    def __get_next_mnemonic_addr(self, mnemonic):
        return mnemonic.address + mnemonic.size


    def __get_full_gadget(self, mnemonic):
        ret = []
        end_mnemonics = ["ret", "jmp", "call"]

        while True:
            ret.append(mnemonic)
            if mnemonic.mnemonic in end_mnemonics:
                return ret
            next_addr = self.__get_next_mnemonic_addr(mnemonic)
            mnemonic = self.mnemonics[next_addr]

    
    def __get_full_gadget_str(self, mnemonic):
        ret = ""

        for mne in self.__get_full_gadget(mnemonic):
            ret += self.__str_mnemonic(mne)
            ret += " -> "

        return ret[:-4]

    def __analyze_pop(self, hd):
        previous_hd = self.dumper.get_prev_hd(hd)
        stack_depth = 1

        while not self.__in_text(previous_hd.value):
            previous_hd = self.dumper.get_prev_hd(previous_hd)
            stack_depth += 1

        if previous_hd.value in self.mnemonics:
            gadgets = self.__get_full_gadget(self.mnemonics[previous_hd.value])
        else:
            return {
                "is_poped": True,
                "register": "unknown"
            }
        
        pop_regs = []
        for g in gadgets:
            if g.mnemonic == "pop":
                pop_regs.append(g.op_str)


        for i, reg in enumerate(pop_regs):
            if i + 1 == stack_depth:
                return {
                    "is_poped": True,
                    "register": reg
                }

        return {"is_poped": False}
