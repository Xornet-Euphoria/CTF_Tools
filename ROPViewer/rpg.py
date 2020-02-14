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
        self.__opt = PseudoOpt(binary, depth)
        self.__binary = Binary(self.__opt)
        self.__rpg_core = Gadgets(self.__binary, self.__opt, 0)
        self.__gadget_list = []

        self.__serach_gadget()

    @property
    def gadget_list(self):
        return self.__gadget_list


    def __serach_gadget(self):
        exec_sections = self.__binary.getExecSections()

        for sct in exec_sections:
            self.__gadget_list += self.__rpg_core.addROPGadgets(sct)
            self.__gadget_list += self.__rpg_core.addSYSGadgets(sct)
            self.__gadget_list += self.__rpg_core.addJOPGadgets(sct)

        self.__gadget_list = self.__rpg_core.passClean(self.__gadget_list, False)

        self.__gadget_list = alphaSortgadgets(self.__gadget_list)


    def dump_gadget(self):
        print(self.__gadget_list[0])
        for gadget in self.__gadget_list:
            print(f"{gadget['vaddr']:x}: {gadget['gadget']}")
