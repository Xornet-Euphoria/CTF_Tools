import re
import os
import subprocess


class Alapod:
    def __init__(self, elf_path):
        if not os.path.isfile(elf_path):
            raise ValueError

        self.elf_path = elf_path

    def symbol_parse(self, symbol):
        command = ["objdump", "-M", "intel", "-d", self.elf_path]
        res = subprocess.run(command, capture_output=True)
        out = res.stdout.decode()

        print(out)


if __name__ == '__main__':
    alpd = Alapod("./test")
    alpd.symbol_parse("pwnme")