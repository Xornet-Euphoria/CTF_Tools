from pwn import ELF
import subprocess
import re
import argparse
from Functions import Functions
from Function import Function
from Section import Section
from Rppp import Rppp


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="analyzing binary tool for pwn")
    parser.add_argument("elf", help="binary path")
    parser.add_argument("-l", "--libc", help="libc path")

    args = parser.parse_args()
    # todo: 引数(実行ファイル、libc, 各項目分離)
    #     : 結果のテキストファイルへの保存
    elf = ELF(args.elf)  # _write4
    libc = ELF(args.libc) if args.libc else None

    print("")
    # dump sections
    print("[+]: all sections")
    sect = Section(elf)
    sect.dump_all_sections()

    print("")
    # all functions
    # todo: 関数の中身を調べる方法(ローカル変数の数やできるなら初期値も調べたい)
    print("[+]: all functions")
    functions = Functions(elf)
    functions.dump_all_functions()
    

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
    
    if libc:
        print("")
        # todo: 結果のパース, オブジェクトとして格納
        # one-gadget
        print("[+]: execute one-gadget")
        one_gadget_command = ["one_gadget", libc.path]
        res = subprocess.run(one_gadget_command, capture_output=True)
        out = res.stdout.decode()
        print(out)
