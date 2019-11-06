import re
import os
import subprocess


class Alapod:
    def __init__(self, elf_path):
        if not os.path.isfile(elf_path):
            raise ValueError

        self.elf_path = elf_path
        
        self.plt_addr_dic = dict()
        self.plt_name_dic = dict()
        self.__parse_plt()


    def __parse_plt(self):
        # parsing .plt section
        plt_addr_dic = dict()
        plt_name_dic = dict()
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
    print(alpd.plt_addr_dic)
    print(alpd.plt_name_dic)
