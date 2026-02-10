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
