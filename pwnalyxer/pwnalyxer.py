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
    parser.add_argument("-s", "--simple", help="only show infomation of section and symbols (not include gadgets and ignore libc)", action="store_true")
    parser.add_argument("--disas", help="disassemble specified function by name (in current version, function only)")
    
    # under construction
    # 目標はradare2の劣化版みたいな解析機能
    parser.add_argument("--detail", help="analyze binary for detail information", action="store_true")

    args = parser.parse_args()
    # todo: 引数(実行ファイル)
    #     : 結果のテキストファイルへの保存 -> リダイレクトで流せばよくない?
    elf = ELF(args.elf)  # _write4
    libc = ELF(args.libc) if args.libc else None

    sect = Section(elf)
    functions = Functions(elf)
    plt = elf.plt
    got = elf.got

    # dump simple
    if not args.disas:
        print("")
        # dump sections
        print("[+]: all sections")
        sect.dump_all_sections()

        print("")
        # all functions
        # todo: 関数の中身を調べる方法(ローカル変数の数やできるなら初期値も調   べたい)
        print("[+]: all functions")
        functions.dump_all_functions()

        # plt
        print("")
        print("[+]: plt")
        table_header = "{0:30} : {1:15}"
        print(table_header.format("symbol name", "address"))
        print("-" * 50)
        for p in plt.items():
            print(table_header.format(p[0], hex(p[1])))

        print("")
        # got
        print("[+]: got")
        print(table_header.format("symbol name", "address"))
        print("-" * 50)
        for g in got.items():
            print(table_header.format(g[0], hex(g[1])))
    
    elif args.disas:
        target = args.disas
        print("")
        target_f = functions.search_function_by_name(target)
        if target_f:
            print("[+]: disassenble function `{}`".format(target))
            target_f.dump_disas()
        else:
            print("[+]: the function `{}` is not found. Please check function name.".format(target))
            print("[+]: all functions are here.")
            functions.dump_all_functions()
        exit(0)

    if args.simple:
        if libc:
            print("")
            print("[notice]: --libc option is set, but ignored")
        exit(0)

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
