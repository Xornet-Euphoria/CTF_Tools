# CTF_Tools

## Tools
### pwn_check.sh
pwnで使いそうなコマンドを一度に実行するツールです。checksec, rp++, rabin2(radare2に同梱), one-gadgetを実行するのでこれらが入ってパスが通っている必要があります(checksecは現時点でpwntoolsの方と競合するので/bin/checksecにおいて直接実行しています)。  
- usage: `./pwn_check.sh <binary>` or `./pwn_check.sh <binary> <libc>`(libcからone-gadgetを検索します)

### pwnalyxer.py
↑のPython版。後発だったがこっちの方が機能が多いし今後もこちらを中心に開発をしていく予定。現時点で引数やオプションについて未実装なので存在だけを示しています。
- usage(予定): `python pwn_check.py <options> <binary>`