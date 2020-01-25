# consts
stdin = 0
stdout = 1
rdonly = 0

# system calls
syscalls_32 = {
    "read": 3,
    "write": 4,
    "open": 5,
    "execve": 11
}

syscalls_64 = {
    "read": 0,
    "write": 1,
    "open": 2,
    "execve": 59
}

# strings
binsh = "/bin/sh"
