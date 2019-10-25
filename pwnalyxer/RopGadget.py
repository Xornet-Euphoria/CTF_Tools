class RopGadget:
    def __init__(self, addr, mnemonic):
        self.addr = addr
        self.mnemonic = mnemonic

    # todo: search registers, type(e.g. mov, call, pop...)