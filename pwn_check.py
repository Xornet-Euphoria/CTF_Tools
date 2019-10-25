from pwn import ELF
import subprocess
import re
from Section import Section
from Rppp import Rppp


# function for parsing rp++
def remove_footer(s):
    index = len(s) - 1
    while index > 0:
        if s[index] == ";":
            return s[0:index]
        index -= 1

    return ""


if __name__ == '__main__':
    # todo: 引数(実行ファイル、libc, 各項目分離)
    #     : 結果のテキストファイルへの保存
    elf = ELF("test")  # _write4
    libc = ELF("libc.so")

    print("")
    # dump sections
    print("[+]: all sections")
    sect = Section(elf)
    sect.dump_all_sections()

    print("")
    # all functions
    # todo: 関数の中身を調べる方法(ローカル変数の数やできるなら初期値も調べたい)
    print("[+]: all functions")
    functions = elf.functions
    # Function(name='pwnme', address=0x4007b5, size=0x52, elf=ELF('/mnt/c/share/ctf/Xornet_Tools/_write4'))
    table_header = "{0:30} : {1:15} ~ {2:15} | {3:10}"
    print(table_header.format("function name", "start address", "end address", "size"))
    print("-" * 80)

    for func in functions.values():
        addr = func.address
        print(table_header.format(func.name, hex(addr), hex(addr + func.size), func.size))

    print("")
    # plt
    print("[+]: plt")
    plt = elf.plt
    table_header = "{0:30} : {1:15}"
    print(table_header.format("symbol name", "address"))
    print("-" * 50)
    for p in plt.items():
        print(table_header.format(p[0], hex(p[1])))

    print("")
    # got
    print("[+]: got")
    got = elf.got
    print(table_header.format("symbol name", "address"))
    print("-" * 50)
    for g in got.items():
        print(table_header.format(g[0], hex(g[1])))

    print("")
    # rp++
    print("[+]: execute rp++")
    rppp = Rppp(elf)
    rppp.dump_all_gadgets()
    
    print("")
    # todo: 結果のパース, オブジェクトとして格納
    # one-gadget
    print("[+]: execute one-gadget")
    one_gadget_command = ["one_gadget", libc.path]
    res = subprocess.run(one_gadget_command, capture_output=True)
    out = res.stdout.decode()
    print(out)
