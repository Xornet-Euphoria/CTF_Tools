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
                print("[+] invalid char of %s: %x (`%c`)" % (input_function, int.from_bytes(c, "little"), int.from_bytes(c, "little")))

    if max_length is not None:
        if len(payload) > max_length:
            if log:
                print("[+] length must be less than or equal to %d" % max_length)
            error_count += 1

    return error_count