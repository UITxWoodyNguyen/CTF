# Crack the Gate 2
### Information
- Category: Web Exploitation
- Points: 200
- Level: Medium

### Description
Our task is to bypass the rate-limiting restriction and log in using the known email address: `ctf-player@picoctf.org` and uncover the hidden secret.

Here is the website:

![](https://media.discordapp.net/attachments/961544480366931969/1432649765610323968/image.png?ex=6901d291&is=69008111&hm=4dc25bf96e437d525f20892de5207e02a10f932fdab43e3f89c45356b6738b6c&=&format=webp&quality=lossless&width=586&height=419)

And it gives us the list of passwords:
```
H3ZdQe9D
4s8RNXkB
G9YKC9r1
J49Q5uuo
ZARenM3b
X68f2Ftm
7IAgfz9e
nL7PeR6k
qz78oOR2
3bVphvph
KbZ5onCD
EfM5yTy8
h9KlW1Gj
oB0UKZ5X
rDRrlgst
xo5MjIYU
K6vkD1ev
yatrLaBx
TcBmTccF
yxMq7WAz
```

### Hint
- What IP does the server think you’re coming from?
- Read more about X-forwarded-For
- You can rotate fake IPs to bypass rate limits.

## Solution
- After testing some wrong password with the same source, we receive a 20-minute time-out. So for each password, we have to tried with another IP Address. Header `X-Forwarded-For` can be used to provide the source IP. We can use BurpSuite to try to login to the web with a random IP Address and a password.
- Brute Force until the flag is returned.
![](https://media.discordapp.net/attachments/961544480366931969/1432658449552117810/image.png?ex=6901daa7&is=69008927&hm=f8485340f49d3200e29181ceb3ffad8df5c7cc22e7b1e4a8a0fe0d7e957d94b8&=&format=webp&quality=lossless&width=1613&height=418)

**The flag is `picoCTF{xff_byp4ss_brut3_3477bf15}`**
