class Mnemonic:
    def __init__(self, addr, raw_mnemonic, detail=False):
        self.addr = addr
        self.raw = raw_mnemonic
        self.opecode = None
        self.operands = []
        self.parsed = detail
        self.comment = ""

        if self.parsed:
            # extract comment
            self.comment = self.get_comment()
            self.__remove_comment()
            self.opecode = self.__get_opecode()
            self.operands = self.__get_operands()


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
