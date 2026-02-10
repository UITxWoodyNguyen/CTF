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
