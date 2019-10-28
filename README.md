# CTF_Tools

## Tools
### pwn_check.sh
pwnで使いそうなコマンドを一度に実行するツールです。checksec, rp++, rabin2(radare2に同梱), one-gadgetを実行するのでこれらが入ってパスが通っている必要があります(checksecは現時点でpwntoolsの方と競合するので/bin/checksecにおいて直接実行しています)。  
- usage: `./pwn_check.sh <binary>` or `./pwn_check.sh <binary> <libc>`(libcからone-gadgetを検索します)

### pwnalyxer.py
↑のPython版。Pwntoolsとrp++, one-gadgetが必要。  
後発だったがこっちの方が機能が多いし今後もこちらを中心に開発をしていく予定。
- usage:
```
usage: pwnalyxer.py [-h] [-l LIBC] [-s] [--symbols [SYMBOLS [SYMBOLS ...]]] [--detail] elf

analyzing binary tool for pwn

positional arguments:
  elf                   binary path

optional arguments:
  -h, --help            show this help message and exit
  -l LIBC, --libc LIBC  libc path
  -s, --simple          only show infomation of section and symbols (not include gadgets and ignore libc)
  --symbols [SYMBOLS [SYMBOLS ...]]
                        show nformation of symbols such as symbol@plt, symbol@got and symbol@libc (-l option is required). This option can get multi arguments.
  --detail              analyze binary for detail information (but not implemented now... sorry)
  ```