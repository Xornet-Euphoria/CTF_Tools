from pwn import ELF
import subprocess
import re

if __name__ == '__main__':
    elf = ELF("test")  # _write4
    libc = ELF("libc.so")

    print("")

    # writable section
    writable_sections = []
    # all sections
    print("[+]: all sections here")
    sections = elf.sections
    table_header = "{0:30} : {1:15} ~ {2:15} | {3:10} | {4:10}"
    print(table_header.format("section name", "start address", "end address", "size", "is readable?"))
    print("-" * 95)
    for section in sections:
        # .data: Container({'sh_name': 248, 'sh_type': 'SHT_PROGBITS', 'sh_flags': 3, 'sh_addr': 6295632, 'sh_offset': 4176, 'sh_size': 16, 'sh_link': 0, 'sh_info': 0, 'sh_addralign': 8, 'sh_entsize': 0})

        # undefined section is skipped
        if section.name == "":
            continue
        header = section.header
        addr = header.sh_addr
        size = header.sh_size
        is_readble = "yes" if (header.sh_flags % 2 == 1) else "no"
        end = addr + size - 1 if size != 0 else 0 
        print(table_header.format(section.name, hex(addr), hex(end), size, is_readble))
        if is_readble:
            writable_sections.append(section)

    print("")
    # all functions
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
    rppp_command = ["rp++", "-f", elf.path, "--unique", "-r", "8"]
    res = subprocess.run(rppp_command, capture_output=True)
    out = res.stdout.decode()
    pattern = r"\x1b\[[0-9]{1,2}m"
    out = re.sub(pattern, "", out)
    print(out)

    print("")
    # one-gadget
    print("[+]: execute one-gadget")
    one_gadget_command = ["one_gadget", libc.path]
    res = subprocess.run(one_gadget_command, capture_output=True)
    out = res.stdout.decode()
    print(out)

