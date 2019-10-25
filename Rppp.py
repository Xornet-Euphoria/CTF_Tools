from pwn import ELF
import subprocess
import re
from RopGadget import RopGadget


class Rppp:
    def __init__(self, elf):
        self.rop_gadgets = []
        self.categorized_gadgets = {
            "call": [],
            "jmp": [],
            "mov": [],
            "pop": [],
            "other": []
        }
        self.__dump_table_format = "{0:10}: {1:}"

        rppp_command = ["rp++", "-f", elf.path, "--unique", "-r", "8"]
        res = subprocess.run(rppp_command, capture_output=True)
        out = res.stdout.decode()

        # 色消し(.txtにする際にゴミが紛れ込むので)
        color_pattern = r"\x1b\[[0-9]{1,2}m"
        out = re.sub(color_pattern, "", out)
        # remove discription and split results
        rppp_pattern = r"0x[0-9a-f]{8}: .*\n"
        match_res = re.findall(rppp_pattern, out)

        # parse results
        for line in match_res:
            addr = int(line[2:10], 16)
            raw_mnemonic = line[12:]
            mnemonic = self.__remove_footer(raw_mnemonic)
            rop_gadget = RopGadget(addr, mnemonic)
            self.rop_gadgets.append(rop_gadget)
            for key in self.categorized_gadgets:
                if key == "other":
                    self.categorized_gadgets["other"].append(rop_gadget)
                elif mnemonic[0:len(key)] == key:
                    self.categorized_gadgets[key].append(rop_gadget)
                    break

    # function for parsing result of rp++
    def __remove_footer(self, s):
        index = len(s) - 1
        while index > 0:
            if s[index] == ";":
                return s[0:index].rstrip()
            index -= 1
    
        return ""


    def __make_table_header(self):
        print(self.__dump_table_format.format("address", "ROP gadget"))
        print("-" * 100)

    def dump_gadgets(self, gadgets):
        self.__make_table_header()
        for gadget in gadgets:
            print(self.__dump_table_format.format(hex(gadget.addr), gadget.mnemonic))


    def dump_all_gadgets(self):
        self.dump_gadgets(self.rop_gadgets)


    def dump_gadgets_by_type(self, mnemonic):
        if mnemonic in self.categorized_gadgets.keys():
            self.dump_gadgets(self.categorized_gadgets[mnemonic])

