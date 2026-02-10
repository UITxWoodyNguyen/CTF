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
