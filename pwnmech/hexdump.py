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


    def dump(self):
        for hd in self.data:
            print(f"{hd.addr}: {hd.dump_string} -> %x" %hd.value)


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
