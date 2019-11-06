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

        self.text_addr_dic = dict()
        self.text_name_dic = dict()
        self.__parse_text()


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
    print(alpd.plt_addr_dic)
    print(alpd.plt_name_dic)
    print(alpd.text_addr_dic)
    print(alpd.text_name_dic)