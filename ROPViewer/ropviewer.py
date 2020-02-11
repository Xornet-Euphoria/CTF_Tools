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

        mode = CS_MODE_64 if self.elf.bits == 64 else CS_MODE_32
        md = Cs(CS_ARCH_X86, mode)
        self.mnemonics = {}

        for mnemonic in md.disasm(self.text.data(), self.text.header.sh_addr):
            self.mnemonics[mnemonic.address] = mnemonic


    def dump(self):
        max_addr = self.dumper.data[-1].addr
        max_byte_length = max_addr.bit_length() // 4 + 1

        fmt_not_rop = f"{{:{max_byte_length}x}}: {{}} -> {{:x}}"
        fmt_rop = f"{{:{max_byte_length}x}}: {{}} -> {{:x}} | {{}}"

        for hd in self.dumper.data:
            if self.__in_text(hd.value):
                print(fmt_rop.format(hd.addr, hd.dump_string, hd.value, self.__get_full_gadget(self.mnemonics[hd.value])))
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
        ret = ""
        end_mnemonics = ["ret", "jmp", "call"]

        while True:
            ret += self.__str_mnemonic(mnemonic)
            if mnemonic.mnemonic in end_mnemonics:
                return ret
            ret += " -> "
            next_addr = self.__get_next_mnemonic_addr(mnemonic)
            mnemonic = self.mnemonics[next_addr]
