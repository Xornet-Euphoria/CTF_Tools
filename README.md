# CTF_Tools

## pwn_check.sh
pwnで使いそうなコマンドを一度に実行するツールです。checksec, rp++, rabin2(radare2に同梱), one-gadgetを実行するのでこれらが入ってパスが通っている必要があります(checksecは現時点でpwntoolsの方と競合するので/bin/checksecにおいて直接実行しています)。  

### usage
`./pwn_check.sh <binary>` or `./pwn_check.sh <binary> <libc>`(libcからone-gadgetを検索します)

## pwnalyxer.py
↑のPython版です。Pwntoolsとrp++, one-gadgetが必要が必要です。  
後発ツールでしたが様々な機能を盛り込み
### usage
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
  --detail              analyze binary for detail information
  ```

### example
- `python pwnalyxer.py <elf>`  
セクション, plt, got, 関数, ROP Gadgetの情報を表示します。  
- `python pwnalyxer.py <elf> -l <libc>`  
↑の情報に加えて存在するならlibc内のOne Gadgetを表示します。  
- `python pwnalyxer.py <elf> -s`  
↑の結果からROP GadgetとOne Gadgetを除いた結果を表示します。libcオプションは無視されます。  
- `python pwnalyxer.py <elf> --symbol <func_name>`  
指定したシンボルの情報を表示します。pltまたはgotに存在するシンボルは両方の位置を表示します。libcオプションが指定されている場合その位置も検索して表示します。  
関数に関しては位置に加えて逆アセンブルを表示します。下記のようにdetailオプションを指定すると詳しい解析を行います。    
- `python pwnalyxer.py <elf> --symbol <func_name1> <func_name2> ...`  
↑の結果を複数のシンボルに関して出力します。但し、シンボルの種類でソートしていません、これは近いうちに実装する予定です。  
- `python pwnalyxer.py <elf> --symbol <func_name1> --detail`  
現在開発中の機能です。関数の逆アセンブル結果を解析し様々な情報を表示します。現在存在するのは次のような情報です。  
  1. 引数の種類の表示  
  2. 数値引数の10進数表示  
  3. callした時に飛ぶアドレスを絶対表示  
  (例1: `sub      rsp, 0x20 (= 32)                # types: 64bit register, num `)  
  (例2: `call     0x400630                        # types: address`)

## ALA-POD
Assembly Language Analyzer with Parsing Objdumpの略  

pwnalyxer.py開発にあたってpwntoolsを利用していたのですが色々と問題が生じた(あるいは生じそう)なので関数シンボル解析部分だけを独立して開発することにしました。現時点で何も出来ていません。  
当面はpwnalyxer.pyの--detailオプションで実装した機能の実装を目指します。

## pwnmech

軽微なpwn用支援関数が定義されているpythonコード、名前の由来はSTARWARSのアストロメク・ドロイドの通称がMechであることから。

### 機能

- check_payload:
ペイロードと入力先の関数(`gets`等)を引数として渡すと入力が中断しないかどうかを確認してくれる関数。ついでに長さチェックもしてくれる

## 制作予定

- pwn_snippet(仮):
事前にpwn用のスニペットを生成してくれる、pwnmechをimportする

- ROP Categorizer(仮):
ROP Gadgetの分類をする、pwn_snippetでimportされるためのpythonファイルを生成する予定
