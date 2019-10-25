from pwn import ELF

class Section:
    def __init__(self, elf):
        self.sections = elf.sections
        self.writable_sections = []
        self.__dump_table_header = "{0:30} : {1:15} ~ {2:15} | {3:10} | {4:10}"

        # search writable sections
        for section in self.sections:
            if section.header.sh_flags % 2 == 1:
                self.writable_sections.append(section)


    def __make_table_header(self):
        print(self.__dump_table_header.format("section name", "start address", "end address", "size", "is writable?"))
        print("-" * 95)


    def dump_sections(self, sections):
        self.__make_table_header()
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
            print(self.__dump_table_header.format(section.name, hex(
                addr), hex(end), size, is_writable))


    def dump_all_sections(self):
        self.dump_sections(self.sections)


    def dump_writable_sections(self):
        self.dump_sections(self.writable_sections)