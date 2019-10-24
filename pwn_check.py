from pwn import ELF
import subprocess
import re


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

    # writable section
    writable_sections = []
    # all sections
    print("[+]: all sections here")
    sections = elf.sections
    table_header = "{0:30} : {1:15} ~ {2:15} | {3:10} | {4:10}"
    print(table_header.format("section name", "start address", "end address", "size", "is writable?"))
    print("-" * 95)
    for section in sections:
        # .data: Container({'sh_name': 248, 'sh_type': 'SHT_PROGBITS', 'sh_flags': 3, 'sh_addr': 6295632, 'sh_offset': 4176, 'sh_size': 16, 'sh_link': 0, 'sh_info': 0, 'sh_addralign': 8, 'sh_entsize': 0})

        # undefined section is skipped
        if section.name == "":
            continue
        header = section.header
        addr = header.sh_addr
        size = header.sh_size
        is_writable = "yes" if (header.sh_flags % 2 == 1) else "no"
        end = addr + size - 1 if size != 0 else 0 
        print(table_header.format(section.name, hex(addr), hex(end), size, is_writable))
        if is_writable:
            writable_sections.append(section)

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
    rop_gadgets = []
    # 有用なGadgetは分類
    categorized_gadgets = {
        "call": [],
        "jmp": [],
        "mov": [],
        "pop": [],
        "other": []
    }
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
        mnemonic = remove_footer(raw_mnemonic).rstrip()
        rop_gadget = {"addr": addr, "mnemonic": mnemonic}
        rop_gadgets.append(rop_gadget)
        for key in categorized_gadgets:
            if key == "other":
                categorized_gadgets["other"].append(rop_gadget)
            if mnemonic[0:len(key)] == key:
                categorized_gadgets[key].append(rop_gadget)
                break

    table_header = "{0:10}: {1:}"
    print(table_header.format("address", "ROP gadget"))
    print("-" * 100)
    for gadget in rop_gadgets:
        print(table_header.format(hex(gadget["addr"]), gadget["mnemonic"]))

    print("")
    # todo: 結果のパース, オブジェクトとして格納
    # one-gadget
    print("[+]: execute one-gadget")
    one_gadget_command = ["one_gadget", libc.path]
    res = subprocess.run(one_gadget_command, capture_output=True)
    out = res.stdout.decode()
    print(out)
