class Mnemonic:
    def __init__(self, addr, raw_mnemonic, detail=False):
        self.addr = addr
        self.raw = raw_mnemonic
        self.opecode = None
        self.raw_operands = []
        self.operands = []
        self.parsed = detail
        self.comment = ""

        if self.parsed:
            # extract comment
            self.comment = self.get_comment()
            self.__remove_comment()
            self.opecode = self.__get_opecode()
            self.raw_operands = self.__get_operands()
            self.__analyze_operands()


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
            return raw.replace(self.opecode, "").strip().split(", ")

        return []


    def __analyze_operands(self):
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
            
            self.operands.append(analyzed_operand)
