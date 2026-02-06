# Crack the Gate 2
### Information
- Category: Web Exploitation
- Points: 200
- Level: Medium

### Description
Our task is to bypass the rate-limiting restriction and log in using the known email address: `ctf-player@picoctf.org` and uncover the hidden secret.

Here is the website:

![](https://cdn.discordapp.com/attachments/961544480366931969/1432649765610323968/image.png?ex=69865151&is=6984ffd1&hm=9280e8f3b8210e3af4c8469578b18fdfa6ece740381df4d2c2925473c2b57dd4&)

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
![](https://cdn.discordapp.com/attachments/961544480366931969/1432658449552117810/image.png?ex=69865967&is=698507e7&hm=751e86c23f330986ffaa5fd65c8be50685bc44edfc40217f6bdd795d6cef86ba&)

**The flag is `picoCTF{xff_byp4ss_brut3_3477bf15}`**
