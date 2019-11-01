from pwn import ELF
import re


class Mnemonic:
    def __init__(self, elf, addr, raw_mnemonic, detail=False, byte_list=None):
        self.elf = elf
        self.addr = addr
        self.raw = raw_mnemonic
        self.opecode = None
        self.raw_operands = []
        self.operands = []
        self.parsed = detail
        self.comment = ""
        self.byte_list = byte_list

        if self.parsed:
            # extract comment
            # self.comment = self.get_comment()
            self.__remove_comment()
            self.opecode = self.__get_opecode()
            self.raw_operands = self.__get_operands()
            self.__analyze_operands()
            self.__analyze_opecode()

    def __get_comment_index(self):
        l = len(self.raw)
        for i in range(l):
            if self.raw[i] == "#":
                return i

        return None


    def get_comment(self):
        i = self.__get_comment_index()
        if i:
            return self.raw[i:]
        else:
            return ""

    
    def __remove_comment(self):
        i = self.__get_comment_index()
        if i:
            self.raw = self.raw[0:i].strip()


    def __get_opecode(self):
        l = len(self.raw)
        for i in range(l):
            if self.raw[i] == " ":
                return self.raw[0:i]
        
        return self.raw


    def __get_operands(self):
        raw = self.raw
        if self.opecode:
            ret = raw.replace(self.opecode, "").strip().split(", ")
            if ret != ['']:
                return ret
            else:
                return []

        return []


    def __analyze_operands(self):
        register_dic = {
            64: ["rax", "rdi", "rsi", "rdx", "rcx", "rbp", "rsp", "rbx", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"],
            32: ["eax", "edi", "esi", "edx", "ecx", "ebp", "esp", "ebx", "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"],
            16: ["ax", "di", "si", "dx", "cx", "bp", "sp", "bx", "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"],
            8: ["al", "dil", "sil", "dl", "cl", "bpl", "spl", "bl", "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"]
        }
        for i, operand in enumerate(self.raw_operands):
            analyzed_operand = {
                "type": "unknown",  # num, addr, register and etc...
                "value": operand
            }
            if operand[0:2] == "0x":
                analyzed_operand["type"] = "num"  # todo: addrとの区別
                num = int(operand, 16)
                num = int.from_bytes((num).to_bytes(8, "little"),
                               "little", signed=True)
                analyzed_operand["value"] = num
                self.raw_operands[i] += " (= {})".format(num)
            elif obj := re.search(r'\[.+\]', operand):
                analyzed_operand["type"] = "address"
                # todo: 式の解析
                expression = operand[obj.start() + 1:obj.end() - 1]
            else:
                for bits, registers in register_dic.items():
                    for register in registers:
                        if operand == register:
                            analyzed_operand["type"] = "{}bit register".format(bits)
                            break
                    else:
                        continue
                    break
            
            self.operands.append(analyzed_operand)

    def __analyze_opecode(self):
        if self.opecode == "call":
            # todo: エラー処理
            byte_list = self.byte_list[1:]
            byte_num = len(byte_list)
            s_num = "0x"
            for b in reversed(byte_list):
                s_b = hex(b)[2:]
                if len(s_b) == 1:
                    s_b = "0" + s_b
                s_num += s_b
            num = int(s_num, 16)
            num = int.from_bytes((num).to_bytes(byte_num, "little"),
                                 "little", signed=True)
            call_addr = self.addr + len(self.byte_list) + num
            self.operands[0]["type"] = "address"
            self.operands[0]["value"] = call_addr
            self.raw_operands[0] = hex(call_addr)
