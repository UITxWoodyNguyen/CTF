# Vernichtet
> Problem Link: https://dreamhack.io/wargame/challenges/2343

## Analyzing
### Phân tích hành vi từ file gốc
- Đề cho một file binary và nhiệm vụ của user là tìm Snake Path trên ma trận 15x15. Kiểm tra bằng command `file`, ta nhận thấy đây là một file ELF 64-bit đã được strip. Chạy thử để phân tích hành vi của file, ta có được kết quả sau:
    ```bash
    $ ./main
    Usage ./main <answer file>
    ```
- Điều này có nghĩa ta cần có một file answer để chạy file binary này. Tạo random một file `test.txt`, ta có được kết quả như sau:
    ```bash
    $ echo "test" > test.txt
    $ ./main test.txt
    Wrong answer.
    ```
- Sử dụng `ltrace` để thu thập thêm thông tin, ta có kết quả sau:
    ```bash
    $ ltrace ./main test.txt
    fopen("test.txt", "rb")                                                                = 0x5aafe9a2e2a0
    fseek(0x5aafe9a2e2a0, 0, 2, 0x77d82851b1a5)                                            = 0
    ftell(0x5aafe9a2e2a0, 0x5aafe9a2e480, 0, 4)                                            = 4 // check file size
    rewind(0x5aafe9a2e2a0, 0, 0, 0)                                                        = 0
    puts("Wrong answer."Wrong answer.
    )                                                                  = 14
    +++ exited (status 0) +++
    ```
- Từ đây, ta nhận xét thấy file binary sẽ thực hiện kiểm tra kích thước file trước khi đọc nội dung.

### Find out Anti-Disassembling
- Thực hiện decompile file với IDA, ta phát hiện nhiều đoạn mã assembly có dạng như sau:
    ```asm
    .text:0000000000001271 loc_1271:                               ; CODE XREF: .text:loc_1271↑j
    .text:0000000000001271                 jmp     short near ptr loc_1271+1
    .text:0000000000001271 ; ---------------------------------------------------------------------------
    .text:0000000000001273                 db 0C1h, 0FFh, 0C9h, 48h, 89h
    .text:0000000000001278                 dq 0FC45C7E87Dh, 0FFEB000000F4E900h, 6348FC458BC9FFC1h
    .text:0000000000001290                 dq 48C00148D08948D0h, 48C9FFC1FFEBC201h, 0FFEB00002D7C058Dh
    .text:00000000000012A8                 dq 0EB0204B60FC9FFC1h, 840FC084C9FFC1FFh, 0EBFC458B000000AFh
    .text:00000000000012C0                 dq 48D06348C9FFC1FFh, 48C9FFC1FFEBD089h, 58D48C20148C001h
    .text:00000000000012D8                 dq 204B60F00002D45h, 0C9FFC1FFEBD0B60Fh, 0C1FFEB04E0C1D089h
    .text:00000000000012F0                 dq 458BC689D029C9FFh, 6348C9FFC1FFEBFCh, 0FFC1FFEBD08948D0h
    .text:0000000000001308                 dq 48C20148C00148C9h, 0B60F00002D0A058Dh, 0FC9FFC1FFEB0204h
    .text:0000000000001320                 dq 48D06348F001C0B6h, 0FFEBD00148E8458Bh, 458B30B60FC9FFC1h
    .text:0000000000001338                 dq 48D08948D06348FCh, 58D48C20148C001h, 204B60F00002CD6h
    .text:0000000000001350                 dq 0C63840C9FFC1FFEBh, 0EB00000000B81C74h, 0FFEB26EBC9FFC1FFh
    .text:0000000000001368                 dq 0C9FFC1FFEBC9FFC1h, 4583C9FFC1FFEB90h, 0E0FC7D8101FCh
    .text:0000000000001380                 dq 0B8FFFFFF048E0F00h
    .text:0000000000001388                 db 1, 3 dup(0), 5Dh, 0C3h
    .text:0000000000001388 ; } // starts at 1269
    ```
- **Nhận xét**: Các đoạn mã này bị làm xáo trộn (ofuscate) với pattern:
    ```asm
    loc_1271:
    jmp     short near ptr loc_1271+1
    db      0C1h, 0FFh, 0C9h, 48h, 89h
    ```
- Đây là kĩ thuật **jmp into middle of instruction**. Cụ thể trong case này:
    - `eb ff` = `jmp -1` (nhảy vào giữa instruction)
    - `c1 ff c9` = `ror ecx, 0xc9` hoặc được hiểu khác tùy context
    - Thực tế `ff c1` = `inc ecx` và `ff c9` = `dec ecx` (NOP equivalent)
- Khi đó **Obfuscation Pattern** trong trường hợp này là `eb ff c1 ff c9` (5 bytes)

### Create Deobfuscate Binary file
- Từ Obfuscation Pattern tìm được ở trên, ta thực hiện patch tất cả các pattern thành NOP (`90, 90, 90, 90, 90`). Script cụ thể:
    ```python
    #!/usr/bin/env python3
    # deobfuscate.py - Patch anti-disassembly patterns

    with open('main', 'rb') as f:
        data = bytearray(f.read())

    # Pattern: eb ff c1 ff c9
    # - eb ff    = jmp short $-1 (nhảy vào byte ff)
    # - ff c1    = inc ecx
    # - ff c9    = dec ecx
    # Thực tế chỉ là NOP vì inc rồi dec lại
    pattern = bytes([0xeb, 0xff, 0xc1, 0xff, 0xc9])
    nops = bytes([0x90, 0x90, 0x90, 0x90, 0x90])

    i = 0
    count = 0
    while i < len(data) - 4:
        if data[i:i+5] == pattern:
            data[i:i+5] = nops
            count += 1
            i += 5
        else:
            i += 1

    print(f"Patched {count} patterns")

    with open('main_deobf', 'wb') as f:
        f.write(data)

    print("Written main_deobf")
    ```
- Sau khi tạo xong file Deobfuscation, thực hiện đối chiếu lại với binary gốc:
    ```bash
    $ ls -la main main_deobf
    -rwxrwxrwx 1 nmt nmt 15160 Apr 30  2025 main
    -rwxrwxrwx 1 nmt nmt 15160 Feb 10 20:02 main_deobf
    ```
- Size của 2 file là như nhau, tiếp tục kiểm tra xem file mới có hoạt động hay không:
    ```bash
    $ chmod +x main_deobf
    $ ./main_deobf test.txt
    Wrong answer.   
    ```
- File vẫn hoạt động bình thường, tiếp tục kiểm tra difference hex:
    ```bash
    $ xxd main | head -100 > main.hex
    $ xxd main_deobf | head -100 > main_deobf.hex
    $ diff main.hex main_deobf.hex | head -20
    ```
- Kết quả trả ra không có difference giữa 2 file, điều đó chứng tỏ file Deobfuscate Binary hoàn toàn đúng.

### Re-Disassembly Deobfuscate Binary File
- Sau khi có được Deobfuscate Binary File, thực hiện disassembly lại một lần nữa theo địa chỉ lấy từ IDA. Ta có kết quả như sau:
    - `main()` - `address = 0x15f5`:
        ```bash
        $ objdump -d -M intel main_deobf > main_deobf.asm
        $ objdump -d -M intel main_deobf | grep -A200 "15f5:"
        15f5:	f3 0f 1e fa          	endbr64
        15f9:	55                   	push   rbp
        15fa:	48 89 e5             	mov    rbp,rsp
        15fd:	48 81 ec 40 01 00 00 	sub    rsp,0x140
        1604:	90                   	nop
        1605:	90                   	nop
        1606:	90                   	nop
        1607:	90                   	nop
        1608:	90                   	nop
        1609:	89 bd cc fe ff ff    	mov    DWORD PTR [rbp-0x134],edi
        160f:	48 89 b5 c0 fe ff ff 	mov    QWORD PTR [rbp-0x140],rsi
        1616:	90                   	nop
        1617:	90                   	nop
        1618:	90                   	nop
        1619:	90                   	nop
        161a:	90                   	nop
        161b:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR fs:0x28
        1622:	00 00 
        1624:	90                   	nop
        1625:	90                   	nop
        1626:	90                   	nop
        1627:	90                   	nop
        1628:	90                   	nop
        1629:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
        162d:	90                   	nop
        162e:	90                   	nop
        162f:	90                   	nop
        1630:	90                   	nop
        1631:	90                   	nop
        1632:	31 c0                	xor    eax,eax
        1634:	83 bd cc fe ff ff 01 	cmp    DWORD PTR [rbp-0x134],0x1
        163b:	7f 28                	jg     1665 <sprintf@plt+0x4f5>
        163d:	48 8d 05 c4 09 00 00 	lea    rax,[rip+0x9c4]        # 2008 <sprintf@plt+0xe98>
        1644:	48 89 c7             	mov    rdi,rax
        1647:	90                   	nop
        1648:	90                   	nop
        1649:	90                   	nop
        164a:	90                   	nop
        164b:	90                   	nop
        164c:	e8 8f fa ff ff       	call   10e0 <puts@plt>
        1651:	90                   	nop
        1652:	90                   	nop
        1653:	90                   	nop
        1654:	90                   	nop
        1655:	90                   	nop
        1656:	b8 00 00 00 00       	mov    eax,0x0
        165b:	e9 47 02 00 00       	jmp    18a7 <sprintf@plt+0x737>
        1660:	90                   	nop
        1661:	90                   	nop
        1662:	90                   	nop
        1663:	90                   	nop
        1664:	90                   	nop
        1665:	48 8b 85 c0 fe ff ff 	mov    rax,QWORD PTR [rbp-0x140]
        166c:	48 83 c0 08          	add    rax,0x8
        1670:	48 8b 00             	mov    rax,QWORD PTR [rax]
        1673:	48 8d 15 a9 09 00 00 	lea    rdx,[rip+0x9a9]        # 2023 <sprintf@plt+0xeb3>
        167a:	48 89 d6             	mov    rsi,rdx
        167d:	48 89 c7             	mov    rdi,rax
        1680:	90                   	nop
        1681:	90                   	nop
        1682:	90                   	nop
        1683:	90                   	nop
        1684:	90                   	nop
        1685:	e8 d6 fa ff ff       	call   1160 <fopen@plt>
        168a:	48 89 85 d0 fe ff ff 	mov    QWORD PTR [rbp-0x130],rax
        1691:	48 83 bd d0 fe ff ff 	cmp    QWORD PTR [rbp-0x130],0x0
        1698:	00 
        1699:	75 23                	jne    16be <sprintf@plt+0x54e>
        169b:	48 8d 05 84 09 00 00 	lea    rax,[rip+0x984]        # 2026 <sprintf@plt+0xeb6>
        16a2:	48 89 c7             	mov    rdi,rax
        16a5:	90                   	nop
        16a6:	90                   	nop
        16a7:	90                   	nop
        16a8:	90                   	nop
        16a9:	90                   	nop
        16aa:	e8 31 fa ff ff       	call   10e0 <puts@plt>
        16af:	b8 00 00 00 00       	mov    eax,0x0
        16b4:	e9 ee 01 00 00       	jmp    18a7 <sprintf@plt+0x737>
        16b9:	90                   	nop
        16ba:	90                   	nop
        16bb:	90                   	nop
        16bc:	90                   	nop
        16bd:	90                   	nop
        16be:	48 8b 85 d0 fe ff ff 	mov    rax,QWORD PTR [rbp-0x130]
        16c5:	ba 02 00 00 00       	mov    edx,0x2
        16ca:	be 00 00 00 00       	mov    esi,0x0
        16cf:	48 89 c7             	mov    rdi,rax
        16d2:	e8 79 fa ff ff       	call   1150 <fseek@plt>
        16d7:	90                   	nop
        16d8:	90                   	nop
        16d9:	90                   	nop
        16da:	90                   	nop
        16db:	90                   	nop
        16dc:	48 8b 85 d0 fe ff ff 	mov    rax,QWORD PTR [rbp-0x130]
        16e3:	90                   	nop
        16e4:	90                   	nop
        16e5:	90                   	nop
        16e6:	90                   	nop
        16e7:	90                   	nop
        16e8:	48 89 c7             	mov    rdi,rax
        16eb:	e8 40 fa ff ff       	call   1130 <ftell@plt>
        16f0:	48 89 85 d8 fe ff ff 	mov    QWORD PTR [rbp-0x128],rax
        16f7:	48 8b 85 d0 fe ff ff 	mov    rax,QWORD PTR [rbp-0x130]
        16fe:	90                   	nop
        16ff:	90                   	nop
        1700:	90                   	nop
        1701:	90                   	nop
        1702:	90                   	nop
        1703:	48 89 c7             	mov    rdi,rax
        1706:	e8 15 fa ff ff       	call   1120 <rewind@plt>
        170b:	90                   	nop
        170c:	90                   	nop
        170d:	90                   	nop
        170e:	90                   	nop
        170f:	90                   	nop
        1710:	48 81 bd d8 fe ff ff 	cmp    QWORD PTR [rbp-0x128],0xe1
        1717:	e1 00 00 00 
        171b:	74 23                	je     1740 <sprintf@plt+0x5d0>
        171d:	48 8d 05 11 09 00 00 	lea    rax,[rip+0x911]        # 2035 <sprintf@plt+0xec5>
        1724:	48 89 c7             	mov    rdi,rax
        1727:	e8 b4 f9 ff ff       	call   10e0 <puts@plt>
        172c:	90                   	nop
        172d:	90                   	nop
        172e:	90                   	nop
        172f:	90                   	nop
        1730:	90                   	nop
        1731:	b8 00 00 00 00       	mov    eax,0x0
        1736:	e9 6c 01 00 00       	jmp    18a7 <sprintf@plt+0x737>
        173b:	90                   	nop
        173c:	90                   	nop
        173d:	90                   	nop
        173e:	90                   	nop
        173f:	90                   	nop
        1740:	90                   	nop
        1741:	90                   	nop
        1742:	90                   	nop
        1743:	90                   	nop
        1744:	90                   	nop
        1745:	48 8b 85 d8 fe ff ff 	mov    rax,QWORD PTR [rbp-0x128]
        174c:	48 89 c7             	mov    rdi,rax
        174f:	e8 ec f9 ff ff       	call   1140 <malloc@plt>
        1754:	48 89 85 e0 fe ff ff 	mov    QWORD PTR [rbp-0x120],rax
        175b:	48 8b b5 d0 fe ff ff 	mov    rsi,QWORD PTR [rbp-0x130]
        1762:	90                   	nop
        1763:	90                   	nop
        1764:	90                   	nop
        1765:	90                   	nop
        1766:	90                   	nop
        1767:	48 8b 95 d8 fe ff ff 	mov    rdx,QWORD PTR [rbp-0x128]
        176e:	48 8b 85 e0 fe ff ff 	mov    rax,QWORD PTR [rbp-0x120]
        1775:	48 89 f1             	mov    rcx,rsi
        1778:	be 01 00 00 00       	mov    esi,0x1
        177d:	48 89 c7             	mov    rdi,rax
        1780:	e8 6b f9 ff ff       	call   10f0 <fread@plt>
        1785:	48 89 85 e8 fe ff ff 	mov    QWORD PTR [rbp-0x118],rax
        178c:	90                   	nop
        178d:	90                   	nop
        178e:	90                   	nop
        178f:	90                   	nop
        1790:	90                   	nop
        1791:	48 8b 85 e8 fe ff ff 	mov    rax,QWORD PTR [rbp-0x118]
        1798:	90                   	nop
        1799:	90                   	nop
        179a:	90                   	nop
        179b:	90                   	nop
        179c:	90                   	nop
        179d:	48 3b 85 d8 fe ff ff 	cmp    rax,QWORD PTR [rbp-0x128]
        17a4:	74 28                	je     17ce <sprintf@plt+0x65e>
        17a6:	48 8d 05 96 08 00 00 	lea    rax,[rip+0x896]        # 2043 <sprintf@plt+0xed3>
        17ad:	90                   	nop
        17ae:	90                   	nop
        17af:	90                   	nop
        17b0:	90                   	nop
        17b1:	90                   	nop
        17b2:	48 89 c7             	mov    rdi,rax
        17b5:	e8 26 f9 ff ff       	call   10e0 <puts@plt>
        17ba:	90                   	nop
        17bb:	90                   	nop
        17bc:	90                   	nop
        17bd:	90                   	nop
        17be:	90                   	nop
        17bf:	b8 00 00 00 00       	mov    eax,0x0
        17c4:	e9 de 00 00 00       	jmp    18a7 <sprintf@plt+0x737>
        17c9:	90                   	nop
        17ca:	90                   	nop
        17cb:	90                   	nop
        17cc:	90                   	nop
        17cd:	90                   	nop
        17ce:	48 8b 85 e0 fe ff ff 	mov    rax,QWORD PTR [rbp-0x120]
        17d5:	48 89 c7             	mov    rdi,rax
        17d8:	90                   	nop
        17d9:	90                   	nop
        17da:	90                   	nop
        17db:	90                   	nop
        17dc:	90                   	nop
        17dd:	e8 87 fa ff ff       	call   1269 <sprintf@plt+0xf9>
        17e2:	83 f0 01             	xor    eax,0x1
        17e5:	84 c0                	test   al,al
        17e7:	74 28                	je     1811 <sprintf@plt+0x6a1>
        17e9:	48 8d 05 45 08 00 00 	lea    rax,[rip+0x845]        # 2035 <sprintf@plt+0xec5>
        17f0:	48 89 c7             	mov    rdi,rax
        ```

    - Hàm Validate 1 - `address = 0x1269`:
        ```bash
        $ objdump -d -M intel main_deobf | grep -A100 "1269:"
        1269:	f3 0f 1e fa          	endbr64
        126d:	55                   	push   rbp
        126e:	48 89 e5             	mov    rbp,rsp
        1271:	90                   	nop
        1272:	90                   	nop
        1273:	90                   	nop
        1274:	90                   	nop
        1275:	90                   	nop
        1276:	48 89 7d e8          	mov    QWORD PTR [rbp-0x18],rdi
        127a:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
        1281:	e9 f4 00 00 00       	jmp    137a <sprintf@plt+0x20a>
        1286:	90                   	nop
        1287:	90                   	nop
        1288:	90                   	nop
        1289:	90                   	nop
        128a:	90                   	nop
        128b:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
        128e:	48 63 d0             	movsxd rdx,eax
        1291:	48 89 d0             	mov    rax,rdx
        1294:	48 01 c0             	add    rax,rax
        1297:	48 01 c2             	add    rdx,rax
        129a:	90                   	nop
        129b:	90                   	nop
        129c:	90                   	nop
        129d:	90                   	nop
        129e:	90                   	nop
        129f:	48 8d 05 7c 2d 00 00 	lea    rax,[rip+0x2d7c]        # 4022 <sprintf@plt+0x2eb2>
        12a6:	90                   	nop
        12a7:	90                   	nop
        12a8:	90                   	nop
        12a9:	90                   	nop
        12aa:	90                   	nop
        12ab:	0f b6 04 02          	movzx  eax,BYTE PTR [rdx+rax*1]
        12af:	90                   	nop
        12b0:	90                   	nop
        12b1:	90                   	nop
        12b2:	90                   	nop
        12b3:	90                   	nop
        12b4:	84 c0                	test   al,al
        12b6:	0f 84 af 00 00 00    	je     136b <sprintf@plt+0x1fb>
        12bc:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
        12bf:	90                   	nop
        12c0:	90                   	nop
        12c1:	90                   	nop
        12c2:	90                   	nop
        12c3:	90                   	nop
        12c4:	48 63 d0             	movsxd rdx,eax
        12c7:	48 89 d0             	mov    rax,rdx
        12ca:	90                   	nop
        12cb:	90                   	nop
        12cc:	90                   	nop
        12cd:	90                   	nop
        12ce:	90                   	nop
        12cf:	48 01 c0             	add    rax,rax
        12d2:	48 01 c2             	add    rdx,rax
        12d5:	48 8d 05 45 2d 00 00 	lea    rax,[rip+0x2d45]        # 4021 <sprintf@plt+0x2eb1>
        12dc:	0f b6 04 02          	movzx  eax,BYTE PTR [rdx+rax*1]
        12e0:	0f b6 d0             	movzx  edx,al
        12e3:	90                   	nop
        12e4:	90                   	nop
        12e5:	90                   	nop
        12e6:	90                   	nop
        12e7:	90                   	nop
        12e8:	89 d0                	mov    eax,edx
        12ea:	c1 e0 04             	shl    eax,0x4
        12ed:	90                   	nop
        12ee:	90                   	nop
        12ef:	90                   	nop
        12f0:	90                   	nop
        12f1:	90                   	nop
        12f2:	29 d0                	sub    eax,edx
        12f4:	89 c6                	mov    esi,eax
        12f6:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
        12f9:	90                   	nop
        12fa:	90                   	nop
        12fb:	90                   	nop
        12fc:	90                   	nop
        12fd:	90                   	nop
        12fe:	48 63 d0             	movsxd rdx,eax
        1301:	48 89 d0             	mov    rax,rdx
        1304:	90                   	nop
        1305:	90                   	nop
        1306:	90                   	nop
        1307:	90                   	nop
        1308:	90                   	nop
        1309:	48 01 c0             	add    rax,rax
        130c:	48 01 c2             	add    rdx,rax
        130f:	48 8d 05 0a 2d 00 00 	lea    rax,[rip+0x2d0a]        # 4020 <sprintf@plt+0x2eb0>
        1316:	0f b6 04 02          	movzx  eax,BYTE PTR [rdx+rax*1]
        131a:	90                   	nop
        131b:	90                   	nop
        131c:	90                   	nop
        131d:	90                   	nop
        131e:	90                   	nop
        131f:	0f b6 c0             	movzx  eax,al
        1322:	01 f0                	add    eax,esi
        1324:	48 63 d0             	movsxd rdx,eax
        1327:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
        132b:	48 01 d0             	add    rax,rdx
        132e:	90                   	nop
        132f:	90                   	nop
        ```
    
    - Hàm Validate 2 - `address = 0x138e`:
        ```bash
        $ objdump -d -M intel main_deobf | grep -A250 "138e:"
        138e:	f3 0f 1e fa          	endbr64
        1392:	55                   	push   rbp
        1393:	48 89 e5             	mov    rbp,rsp
        1396:	48 89 7d d8          	mov    QWORD PTR [rbp-0x28],rdi
        139a:	90                   	nop
        139b:	90                   	nop
        139c:	90                   	nop
        139d:	90                   	nop
        139e:	90                   	nop
        139f:	c6 45 e5 00          	mov    BYTE PTR [rbp-0x1b],0x0
        13a3:	c6 45 e6 00          	mov    BYTE PTR [rbp-0x1a],0x0
        13a7:	c7 45 ec 00 00 00 00 	mov    DWORD PTR [rbp-0x14],0x0
        13ae:	e9 86 00 00 00       	jmp    1439 <sprintf@plt+0x2c9>
        13b3:	90                   	nop
        13b4:	90                   	nop
        13b5:	90                   	nop
        13b6:	90                   	nop
        13b7:	90                   	nop
        13b8:	c7 45 f0 00 00 00 00 	mov    DWORD PTR [rbp-0x10],0x0
        13bf:	90                   	nop
        13c0:	90                   	nop
        13c1:	90                   	nop
        13c2:	90                   	nop
        13c3:	90                   	nop
        13c4:	eb 5f                	jmp    1425 <sprintf@plt+0x2b5>
        13c6:	90                   	nop
        13c7:	90                   	nop
        13c8:	90                   	nop
        13c9:	90                   	nop
        13ca:	90                   	nop
        13cb:	90                   	nop
        13cc:	90                   	nop
        13cd:	90                   	nop
        13ce:	90                   	nop
        13cf:	90                   	nop
        13d0:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
        13d3:	89 d0                	mov    eax,edx
        13d5:	c1 e0 04             	shl    eax,0x4
        13d8:	29 d0                	sub    eax,edx
        13da:	90                   	nop
        13db:	90                   	nop
        13dc:	90                   	nop
        13dd:	90                   	nop
        13de:	90                   	nop
        13df:	89 c6                	mov    esi,eax
        13e1:	90                   	nop
        13e2:	90                   	nop
        13e3:	90                   	nop
        13e4:	90                   	nop
        13e5:	90                   	nop
        13e6:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
        13e9:	01 f0                	add    eax,esi
        13eb:	48 63 d0             	movsxd rdx,eax
        13ee:	90                   	nop
        13ef:	90                   	nop
        13f0:	90                   	nop
        13f1:	90                   	nop
        13f2:	90                   	nop
        13f3:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
        13f7:	90                   	nop
        13f8:	90                   	nop
        13f9:	90                   	nop
        13fa:	90                   	nop
        13fb:	90                   	nop
        13fc:	48 01 d0             	add    rax,rdx
        13ff:	90                   	nop
        1400:	90                   	nop
        1401:	90                   	nop
        1402:	90                   	nop
        1403:	90                   	nop
        1404:	0f b6 00             	movzx  eax,BYTE PTR [rax]
        1407:	3c 01                	cmp    al,0x1
        1409:	75 16                	jne    1421 <sprintf@plt+0x2b1>
        140b:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
        140e:	90                   	nop
        140f:	90                   	nop
        1410:	90                   	nop
        1411:	90                   	nop
        1412:	90                   	nop
        1413:	88 45 e5             	mov    BYTE PTR [rbp-0x1b],al
        1416:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
        1419:	90                   	nop
        141a:	90                   	nop
        141b:	90                   	nop
        141c:	90                   	nop
        141d:	90                   	nop
        141e:	88 45 e6             	mov    BYTE PTR [rbp-0x1a],al
        1421:	83 45 f0 01          	add    DWORD PTR [rbp-0x10],0x1
        1425:	90                   	nop
        1426:	90                   	nop
        1427:	90                   	nop
        1428:	90                   	nop
        1429:	90                   	nop
        142a:	83 7d f0 0e          	cmp    DWORD PTR [rbp-0x10],0xe
        142e:	7e 9b                	jle    13cb <sprintf@plt+0x25b>
        1430:	83 45 ec 01          	add    DWORD PTR [rbp-0x14],0x1
        1434:	90                   	nop
        1435:	90                   	nop
        1436:	90                   	nop
        1437:	90                   	nop
        1438:	90                   	nop
        1439:	83 7d ec 0e          	cmp    DWORD PTR [rbp-0x14],0xe
        143d:	0f 8e 70 ff ff ff    	jle    13b3 <sprintf@plt+0x243>
        1443:	c7 45 f4 01 00 00 00 	mov    DWORD PTR [rbp-0xc],0x1
        144a:	e9 8d 01 00 00       	jmp    15dc <sprintf@plt+0x46c>
        144f:	80 7d e5 00          	cmp    BYTE PTR [rbp-0x1b],0x0
        1453:	7e 16                	jle    146b <sprintf@plt+0x2fb>
        1455:	0f b6 45 e5          	movzx  eax,BYTE PTR [rbp-0x1b]
        1459:	90                   	nop
        145a:	90                   	nop
        145b:	90                   	nop
        145c:	90                   	nop
        145d:	90                   	nop
        145e:	83 e8 01             	sub    eax,0x1
        1461:	88 45 e7             	mov    BYTE PTR [rbp-0x19],al
        1464:	eb 11                	jmp    1477 <sprintf@plt+0x307>
        1466:	90                   	nop
        1467:	90                   	nop
        1468:	90                   	nop
        1469:	90                   	nop
        146a:	90                   	nop
        146b:	0f b6 45 e5          	movzx  eax,BYTE PTR [rbp-0x1b]
        146f:	90                   	nop
        1470:	90                   	nop
        1471:	90                   	nop
        1472:	90                   	nop
        1473:	90                   	nop
        1474:	88 45 e7             	mov    BYTE PTR [rbp-0x19],al
        1477:	80 7d e5 0d          	cmp    BYTE PTR [rbp-0x1b],0xd
        147b:	7f 16                	jg     1493 <sprintf@plt+0x323>
        147d:	0f b6 45 e5          	movzx  eax,BYTE PTR [rbp-0x1b]
        1481:	90                   	nop
        1482:	90                   	nop
        1483:	90                   	nop
        1484:	90                   	nop
        1485:	90                   	nop
        1486:	83 c0 01             	add    eax,0x1
        1489:	90                   	nop
        148a:	90                   	nop
        148b:	90                   	nop
        148c:	90                   	nop
        148d:	90                   	nop
        148e:	88 45 e8             	mov    BYTE PTR [rbp-0x18],al
        1491:	eb 07                	jmp    149a <sprintf@plt+0x32a>
        1493:	0f b6 45 e5          	movzx  eax,BYTE PTR [rbp-0x1b]
        1497:	88 45 e8             	mov    BYTE PTR [rbp-0x18],al
        149a:	90                   	nop
        149b:	90                   	nop
        149c:	90                   	nop
        149d:	90                   	nop
        149e:	90                   	nop
        149f:	80 7d e6 00          	cmp    BYTE PTR [rbp-0x1a],0x0
        14a3:	7e 1b                	jle    14c0 <sprintf@plt+0x350>
        14a5:	90                   	nop
        14a6:	90                   	nop
        14a7:	90                   	nop
        14a8:	90                   	nop
        14a9:	90                   	nop
        14aa:	0f b6 45 e6          	movzx  eax,BYTE PTR [rbp-0x1a]
        14ae:	83 e8 01             	sub    eax,0x1
        14b1:	88 45 e9             	mov    BYTE PTR [rbp-0x17],al
        14b4:	90                   	nop
        14b5:	90                   	nop
        14b6:	90                   	nop
        14b7:	90                   	nop
        14b8:	90                   	nop
        14b9:	eb 0c                	jmp    14c7 <sprintf@plt+0x357>
        14bb:	90                   	nop
        14bc:	90                   	nop
        14bd:	90                   	nop
        14be:	90                   	nop
        14bf:	90                   	nop
        14c0:	0f b6 45 e6          	movzx  eax,BYTE PTR [rbp-0x1a]
        14c4:	88 45 e9             	mov    BYTE PTR [rbp-0x17],al
        14c7:	80 7d e6 0d          	cmp    BYTE PTR [rbp-0x1a],0xd
        14cb:	7f 20                	jg     14ed <sprintf@plt+0x37d>
        14cd:	90                   	nop
        14ce:	90                   	nop
        14cf:	90                   	nop
        14d0:	90                   	nop
        14d1:	90                   	nop
        14d2:	0f b6 45 e6          	movzx  eax,BYTE PTR [rbp-0x1a]
        14d6:	90                   	nop
        14d7:	90                   	nop
        14d8:	90                   	nop
        14d9:	90                   	nop
        14da:	90                   	nop
        14db:	83 c0 01             	add    eax,0x1
        14de:	90                   	nop
        14df:	90                   	nop
        14e0:	90                   	nop
        14e1:	90                   	nop
        14e2:	90                   	nop
        14e3:	88 45 ea             	mov    BYTE PTR [rbp-0x16],al
        14e6:	90                   	nop
        14e7:	90                   	nop
        14e8:	90                   	nop
        14e9:	90                   	nop
        14ea:	90                   	nop
        14eb:	eb 0c                	jmp    14f9 <sprintf@plt+0x389>
        14ed:	0f b6 45 e6          	movzx  eax,BYTE PTR [rbp-0x1a]
        14f1:	90                   	nop
        14f2:	90                   	nop
        14f3:	90                   	nop
        14f4:	90                   	nop
        14f5:	90                   	nop
        14f6:	88 45 ea             	mov    BYTE PTR [rbp-0x16],al
        14f9:	c6 45 eb 00          	mov    BYTE PTR [rbp-0x15],0x0
        14fd:	0f be 45 e9          	movsx  eax,BYTE PTR [rbp-0x17]
        1501:	90                   	nop
        1502:	90                   	nop
        1503:	90                   	nop
        1504:	90                   	nop
        1505:	90                   	nop
        1506:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
        1509:	e9 9c 00 00 00       	jmp    15aa <sprintf@plt+0x43a>
        150e:	90                   	nop
        150f:	90                   	nop
        1510:	90                   	nop
        1511:	90                   	nop
        1512:	90                   	nop
        1513:	90                   	nop
        1514:	90                   	nop
        1515:	90                   	nop
        1516:	90                   	nop
        1517:	90                   	nop
        1518:	0f be 45 e7          	movsx  eax,BYTE PTR [rbp-0x19]
        151c:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
        151f:	90                   	nop
        1520:	90                   	nop
        1521:	90                   	nop
        1522:	90                   	nop
        1523:	90                   	nop
        1524:	eb 72                	jmp    1598 <sprintf@plt+0x428>
        1526:	90                   	nop
        1527:	90                   	nop
        1528:	90                   	nop
        1529:	90                   	nop
        152a:	90                   	nop
        152b:	0f be 45 e6          	movsx  eax,BYTE PTR [rbp-0x1a]
        152f:	39 45 f8             	cmp    DWORD PTR [rbp-0x8],eax
        1532:	75 0e                	jne    1542 <sprintf@plt+0x3d2>
        1534:	90                   	nop
        1535:	90                   	nop
        1536:	90                   	nop
        1537:	90                   	nop
        1538:	90                   	nop
        1539:	0f be 45 e5          	movsx  eax,BYTE PTR [rbp-0x1b]
        153d:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
        1540:	74 4c                	je     158e <sprintf@plt+0x41e>
        1542:	90                   	nop
        ```
- Từ đây, ta có được flow của 3 hàm này như sau:
    - `main()`:
        ```c++
        int main(int argc, char** argv) {
            FILE* fp;
            char* buffer;
            long file_size;
            char command[512];

            if (argc < 2) {
                print_usage(argv[0]);
                return 1;
            }

            // Attempt to open the provided answer file
            fp = fopen(argv[1], "rb");
            if (fp == NULL) {
                puts("File Not Found");
                return 1;
            }

            // Get file size
            fseek(fp, 0, SEEK_END);
            file_size = ftell(fp);
            rewind(fp);

            // Allocate memory and read file
            buffer = (char*)malloc(file_size + 1);
            if (fread(buffer, 1, file_size, fp) != file_size) {
                puts("Fread failed");
                free(buffer);
                fclose(fp);
                return 1;
            }
            buffer[file_size] = '\0';
            fclose(fp);

            /* The assembly contains a complex data block starting at 0x4020.
            This looks like a custom VM or a obfuscated state machine that 
            eventually triggers a hash check. 
            The command string at 0x2050 is: 
            "bash -c \"echo DH{$(sha256sum '%s' | awk '{print $1}')}\""
            */

            // Reconstructing the logic of the string formatting at 0x1170 and system call at 0x1110:
            sprintf(command, "bash -c \"echo DH{$(sha256sum '%s' | awk '{print $1}')}\"", argv[1]);
            
            // In the real binary, it compares the result of the file processing
            // against the internal expected value.
            
            // If the check passes:
            puts("Correct!");
            
            // If it fails:
            // puts("Wrong answer.");

            free(buffer);
            return 0;
        }
        ```
    - Validation 1:
        ```c++
        for (int i = 0; i < 0xe0; i++) {
            int col = table[i*3];      // offset 0x4020
            int row = table[i*3 + 1];  // offset 0x4021
            int expected = table[i*3 + 2]; // offset 0x4022
            
            if (expected == 0) break;  // Terminator
            
            int pos = col + row * 15;
            if (input[pos] != expected)
                return 0;
        }
        return 1;
        ```
    - Validation 2:
        ```c++
        // Tìm vị trí của giá trị 1
        for (row = 0; row <= 14; row++) {
            for (col = 0; col <= 14; col++) {
                if (input[col + row*15] == 1) {
                    start_col = col;
                    start_row = row;
                }
            }
        }

        // Kiểm tra path từ 1 đến 225
        for (val = 1; val < 225; val++) {
            // Tìm val+1 trong các ô lân cận 8 hướng
            found = false;
            for each neighbor of (current_col, current_row):
                if (input[neighbor] == val + 1):
                    found = true;
                    move to neighbor;
                    break;
            if (!found) return 0;
        }
        return 1;
        ```

### Get Table Constraints
- Source code lấy Table:
    ```python
    with open('main', 'rb') as f:
        f.seek(0x3020)
        table_data = f.read(450)

    for i in range(150):
        col = table_data[i*3]
        row = table_data[i*3 + 1]
        expected = table_data[i*3 + 2]
        if expected == 0:
            break
        pos = col + row * 15
        print(f"pos {pos} (col={col}, row={row}) = {expected}")
    ```

### Finding Snake Path
#### Thuật toán
**Bài toán:**
- Lưới 15x15 = 225 ô
- 150 ô có giá trị cố định (từ table)
- 75 ô trống cần điền
- Các giá trị 1-225 phải tạo thành đường đi liên tục (8 hướng adjacent)

**Thuật toán: Backtracking**

1. Parse table để biết giá trị nào ở vị trí nào
2. Tìm các "gaps" - khoảng trống giữa các giá trị liên tiếp
3. Với mỗi gap (v1 → v2), tìm đường đi từ pos(v1) đến pos(v2) qua các ô trống
4. Dùng backtracking để thử các đường đi khả thi

#### Source code:
    ```python
    def solve_all_gaps(gap_idx, solution, filled):
    if gap_idx >= len(gaps):
        return True  # Solved!
    
    v1, v2, missing = gaps[gap_idx]
    p1, p2 = exp_to_pos[v1], exp_to_pos[v2]
    
    # Tìm tất cả đường đi có độ dài đúng
    for path in find_paths(p1, p2, len(missing) + 1):
        # Thử path này
        for i, p in enumerate(path):
            solution[p] = missing[i]
            filled.add(p)
        
        if solve_all_gaps(gap_idx + 1, solution, filled):
            return True
        
        # Backtrack
        for p in path:
            solution[p] = 0
            filled.remove(p)
    
    return False
    ```

### Reversing
- Từ phân tích trên, ta có source code sau:
    ```python
    #!/usr/bin/env python3
    def solve():
        # Read table from binary
        with open('main', 'rb') as f:
            f.seek(0x3020)  # Table at 0x4020 - 0x1000 (PIE offset)
            table_data = f.read(450)

        # Parse constraints from table
        exp_to_pos = {}
        pos_to_exp = {}
        for i in range(150):
            col = table_data[i*3]
            row = table_data[i*3 + 1]
            expected = table_data[i*3 + 2]
            if expected == 0:
                break
            pos = col + row * 15
            exp_to_pos[expected] = pos
            pos_to_exp[pos] = expected

        def get_neighbors(pos):
            """Get 8-way adjacent positions"""
            col = pos % 15
            row = pos // 15
            return [pos+dc+dr*15 for dc in [-1,0,1] for dr in [-1,0,1] 
                    if (dc != 0 or dr != 0) and 0 <= col+dc < 15 and 0 <= row+dr < 15]

        # Find all gaps (missing values between defined ones)
        gaps = []
        sorted_vals = sorted(exp_to_pos.keys())
        for i in range(len(sorted_vals) - 1):
            v1, v2 = sorted_vals[i], sorted_vals[i+1]
            if v2 - v1 > 1:
                gaps.append((v1, v2, list(range(v1+1, v2))))

        print(f"Table has {len(pos_to_exp)} fixed values")
        print(f"Found {len(gaps)} gaps with {sum(len(g[2]) for g in gaps)} missing values")

        # Backtracking solver
        def solve_all_gaps(gap_idx, solution, filled):
            if gap_idx >= len(gaps):
                return True
            
            v1, v2, missing = gaps[gap_idx]
            p1 = exp_to_pos[v1]
            p2 = exp_to_pos[v2]
            
            def find_paths(current, end, steps_left, path):
                """Generator for all valid paths of exact length"""
                if steps_left == 1:
                    if end in get_neighbors(current):
                        yield path
                    return
                
                for npos in get_neighbors(current):
                    if npos == end or npos in filled or npos in path:
                        continue
                    yield from find_paths(npos, end, steps_left - 1, path + [npos])
            
            steps = len(missing) + 1
            for path in find_paths(p1, p2, steps, []):
                if len(path) != len(missing):
                    continue
                
                # Try this path
                for i, p in enumerate(path):
                    solution[p] = missing[i]
                    filled.add(p)
                
                if solve_all_gaps(gap_idx + 1, solution, filled):
                    return True
                
                # Backtrack
                for p in path:
                    solution[p] = 0
                    filled.remove(p)
            
            return False

        # Initialize with fixed values
        solution = [0] * 225
        filled = set()
        for pos, val in pos_to_exp.items():
            solution[pos] = val
            filled.add(pos)

        # Solve
        if solve_all_gaps(0, solution, filled):
            print("Solution found!")
            
            # Verify
            val_to_pos = {v: i for i, v in enumerate(solution)}
            errors = sum(1 for v in range(1, 225) 
                        if val_to_pos.get(v+1) not in get_neighbors(val_to_pos.get(v, -1)))
            print(f"Verification errors: {errors}")
            
            # Write solution
            with open('answer.bin', 'wb') as f:
                f.write(bytes(solution))
            print("Written answer.bin")
            print("\nRun: ./main answer.bin")
        else:
            print("No solution found!")

    if __name__ == "__main__":
        solve()
    ```

- Sau khi chạy source để tạo `answer.bin`, thực hiện chạy file theo cú pháp ban đầu để lấy flag:
    ```bash
    ./main answer.bin
    Correct!
    DH{e309147b588c517bb4100064d6185e5430ebad23d83e601327c4907bb0232292}
    ```

### Conclusion
| Kỹ thuật | Mô tả |
|----------|-------|
| Anti-disassembly | Pattern `eb ff c1 ff c9` làm IDA hiểu sai code flow |
| Stripped binary | Không có symbol, khó trace function |
| Two-stage validation | Kiểm tra table constraints + snake path connectivity |
| Snake path puzzle | Bài toán pathfinding trên lưới với constraints |