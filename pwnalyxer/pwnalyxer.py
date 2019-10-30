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
    parser.add_argument("--symbols", nargs="*",
                        help="show nformation of symbols such as symbol@plt, symbol@got and symbol@libc (-l option is required). This option can get multi arguments.")
    
    # under construction
    # 目標はradare2の劣化版みたいな解析機能
    parser.add_argument("--detail", help="analyze binary for detail information (but not implemented now... sorry)", action="store_true")

    args = parser.parse_args()

    # analyze binary
    # todo: 不要な解析を無視
    elf = ELF(args.elf)  # _write4
    libc = ELF(args.libc) if args.libc else None

    sect = Section(elf)
    functions = Functions(elf)
    plt = elf.plt
    got = elf.got

    # dump simple
    if not args.symbols:
        print("")
        # dump sections
        print("[+]: all sections")
        sect.dump_all_sections()

        print("")
        # all functions
        # todo: 関数の中身を調べる方法(ローカル変数の数やできるなら初期値も調べたい)
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
    elif args.symbols:
        # todo: sort type (functions or other symbols)
        #     : symbol class
        for symbol in args.symbols:
            print("")
            print("[+]: informations about symbol `{}`".format(symbol))
            # python 3.8 is required
            if f := functions.search_function_by_name(symbol):
                print("")
                functions.dump_functions([f])
                print("")
                print("[+]: disassenble function `{}`".format(symbol))
                print("{0:15}: {1:8} {2} {3}".format("address", "opecode", "operands", "comment"))
                print("-" * 60)
                f.dump_disas(args.detail)

            elif symbol in plt and symbol in got:
                table_header = "{0:15}: {1:30}"
                print(table_header.format("name@place", "address"))
                print("-" * 50)
                print(table_header.format(symbol + "@plt", hex(plt[symbol])))
                print(table_header.format(symbol + "@got", hex(got[symbol])))
            
                if libc and symbol in libc.symbols:
                    print(table_header.format(symbol + "@libc", hex(libc.symbols[symbol])))
            else:
                print("[+]: symbol `{}` is not function and in libc.".format(symbol))

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
