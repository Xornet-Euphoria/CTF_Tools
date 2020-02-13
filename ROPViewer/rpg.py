from ropgadget.binary import Binary
from ropgadget.gadgets import Gadgets
from ropgadget.rgutils import alphaSortgadgets


class PseudoOpt:
    def __init__(self, binary, depth=10):
        self.binary = binary
        self.rawArch = False
        self.depth = depth


class RPG:
    def __init__(self, binary, depth=20):
        self.depth = depth
        self.opt = PseudoOpt(binary, depth)
        self.binary = Binary(self.opt)
        self.rpgadget_core = Gadgets(self.binary, self.opt, 0)
        self.__gadget_list = []

        self.__serach_gadget()

    @property
    def gadget_list(self):
        return self.__gadget_list


    def __serach_gadget(self):
        exec_sections = self.binary.getExecSections()

        for sct in exec_sections:
            self.__gadget_list += self.rpgadget_core.addROPGadgets(sct)
            self.__gadget_list += self.rpgadget_core.addSYSGadgets(sct)
            self.__gadget_list += self.rpgadget_core.addJOPGadgets(sct)

        self.__gadget_list = self.rpgadget_core.passClean(self.__gadget_list, False)

        self.__gadget_list = alphaSortgadgets(self.__gadget_list)


    def dump_gadget(self):
        print(self.__gadget_list[0])
        for gadget in self.__gadget_list:
            print(f"{gadget['vaddr']:x}: {gadget['gadget']}")
