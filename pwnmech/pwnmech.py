from binascii import hexlify
from pwn import p32, p64


def check_payload(payload, input_function=None, max_length=None, stop=False, log=False):
    error_count = 0
    # check black list char
    if input_function == "fgets" or input_function == "gets":
        # \n
        blacklist = [0x0a]
    elif input_function == "scanf":
        blacklist = list(range(0x09, 0x0d + 1))
        blacklist.append(0x20)
    elif input_function == "read":
        blacklist = []
    else:
        raise ValueError

    for i in blacklist:
        c = i.to_bytes(1, "little")
        if c in payload:
            error_count += 1

            if log:
                print("[+] invalid char of %s: %x (`%c`)" % (input_function,
                                                             int.from_bytes(c, "little"), int.from_bytes(c, "little")))

    if max_length is not None:
        if len(payload) > max_length:
            if log:
                print("[+] length must be less than or equal to %d" %
                      max_length)
            error_count += 1

    return error_count


"""
    ================= tools for shellcode =================
"""

def str_to_long(s):
    return int(hexlify(s.encode()), 16)


def split_string(s, x64=False):
    word = 8 if x64 else 4
    s += "\x00"

    while len(s) % word != 0:
        s += "\x00"

    pushs = []
    index = len(s)
    while index >= word:
        pushs.append(s[index - word:index][::-1])
        index -= word

    return pushs


def push_string(s, x64=False):
    shellcode = ""

    pushs = split_string(s, x64)

    for operand in pushs:
        mnemonic = ope_without_null("push", str_to_long(operand))
        shellcode += mnemonic

    return shellcode


def ope_without_null(ope, num, reg="rax", x64=False):
    if ope != "mov" and ope != "push":
        raise ValueError
    f = p64 if x64 else p32
    packed_num = f(num)

    if b"\x00" not in packed_num:
        return "%s 0x%x\n" % (ope, num)

    # mov <reg>, <non zero num1>; xor <reg>, <non zero num2>; push <reg>
    bytes1 = b""
    bytes2 = b""

    for b in packed_num:
        for b1 in range(1, 256):
            b2 = b ^ b1
            if b2 != 0:
                bytes1 += b1.to_bytes(1, "big")
                bytes2 += b2.to_bytes(1, "big")
                break
                
                
    shellcode = "mov %s, 0x%x\n" % (reg, int(hexlify(bytes1), 16))
    shellcode += "xor %s, 0x%x\n" % (reg, int(hexlify(bytes2), 16))
    
    if ope == "push":
        shellcode += "push %s\n" % reg

    return shellcode