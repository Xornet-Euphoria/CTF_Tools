from Mnemonic import Mnemonic


class RopGadget:
    def __init__(self, addr, raw_mnemonic):
        self.addr = addr
        self.raw_mnemonic = raw_mnemonic
        self.mnemonics = raw_mnemonic.split(";")

    # todo: search registers, type(e.g. mov, call, pop...)