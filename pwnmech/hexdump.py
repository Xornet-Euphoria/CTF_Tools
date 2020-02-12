from pwn import unpack


"""
    ================= tools for hexdump =================
"""

class HexDumper:
    def __init__(self, data, byte_num=4, base_addr=0, endian="little"):
        self.raw_data = data
        self.byte_num = byte_num
        self.base_addr = base_addr
        self.endian = endian
        self.data = self.__process_data()
        self.unpackable = self.byte_num == 4 or self.byte_num == 8  # 8bit, 16bitに対応するかもしれない


    def __get_hd_by_addr(self, addr):
        current_index = (addr - self.base_addr) // self.byte_num
        return self.data[current_index]


    def get_prev_hd(self, hd):
        prev_addr = hd.addr - self.base_addr - self.byte_num
        return __get_hd_by_addr(prev_addr)


    def get_next_hd(self, hd):
        next_addr = hd.addr - self.base_addr + self.byte_num
    

    def __process_data(self):
        ret_data = []
        offset = 0
        while offset < len(self.raw_data):
            if offset + self.byte_num < len(self.raw_data):
                word = self.raw_data[offset:offset+self.byte_num]
            else:
                word = self.raw_data[offset:]
                while len(word) < self.byte_num:
                    word += b"\x00"

            hd = HexData(word, self.base_addr + offset)
            ret_data.append(hd)
            offset += self.byte_num

        return ret_data


    # simple dump
    def dump(self, fmt=None):
        if not self.unpackable:
            self.raw_dump()
            return

        if fmt is None:
            max_addr = self.data[-1].addr
            max_byte_length = max_addr.bit_length() // 4 + 1

            fmt = f"{{:{max_byte_length}x}}: {{}} -> {{:x}}"

        for hd in self.data:
            print(fmt.format(hd.addr, hd.dump_string, hd.value))


    def raw_dump(self, fmt=None):
        if fmt is None:
            max_addr = self.data[-1].addr
            max_byte_length = max_addr.bit_length() // 4 + 1

            fmt = f"{{:{max_byte_length}x}}: {{}}"

        for hd in self.data:
            print(fmt.format(hd.addr, hd.dump_string))

    
    def string_dump(self, non_char=".", fmt=None):
        if fmt is None:
            max_addr = self.data[-1].addr
            max_byte_length = max_addr.bit_length() // 4 + 1

            fmt = f"{{:{max_byte_length}x}}: {{}} | {{}}"

        for hd in self.data:
            s = ""
            for c in hd.raw_data:
                if c > 0x1f and c < 0x7f:
                    s += chr(c)
                else:
                    s += non_char

            print(fmt.format(hd.addr, hd.dump_string, s))


class HexData:
    def __init__(self, data, addr, endian="little"):
        self.raw_data = data
        self.addr = addr
        self.byte_num = len(data)
        self.unpackable = self.byte_num == 4 or self.byte_num == 8  # 8bit, 16bitに対応するかもしれない
        self.dump_string = self.__make_dump_string()
        self.value = self.__unpack(endian) if self.unpackable else None

    
    def __make_dump_string(self):
        dumped = ""
        for c in self.raw_data:
            if c < 16:
                dumped += "0"
            dumped += hex(c)[2:]

            dumped += " "

        dumped = dumped[:-1]
        return dumped
        
    
    def __unpack(self, endian):
        return unpack(self.raw_data, self.byte_num * 8, endian=endian)


def filedump(filename, byte_num, endian="little", fmt=None):
    fdata = open(filename, "rb").read()

    dumper = HexDumper(fdata, byte_num, endian=endian)
    dumper.dump(fmt=fmt)
