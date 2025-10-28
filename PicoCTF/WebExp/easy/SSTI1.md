# SSTI1

### Information
- Category: Web Exploitation
- Level: Easy

### Description
We need to inject this website to get the flag.

![](https://media.discordapp.net/attachments/961544480366931969/1432623415159947357/image.png?ex=6901ba07&is=69006887&hm=847e4adf11bdbc3c01420750ac191d47aa0f44f9de7bfc986a01ced1b2627424&=&format=webp&quality=lossless&width=754&height=255)

### Hint
- Server Side Template Injection

## Solution
- First, we try some basic input to know how this web work. I have tried `3+7` and `{{3+7}}`, and here is the result from this web:

![](https://media.discordapp.net/attachments/961544480366931969/1432624120138436658/image.png?ex=6901baaf&is=6900692f&hm=62ef1853bca8567388714ea9369df7a46d0d5ca308d89d0e04e61dcd8d35ecaf&=&format=webp&quality=lossless&width=606&height=326)

![](https://media.discordapp.net/attachments/961544480366931969/1432624204511055973/image.png?ex=6901bac3&is=69006943&hm=f9027caf12496333e4aeb5dd6ab3c4c8f553c483228000d3afbe5ab478f7d94e&=&format=webp&quality=lossless&width=543&height=421)

- We can see that nothing happened with a normal input. So we have to tried a more sophisticated payload, which can perform a RCE (Remote Code Execusion) on the server.
- First, we use `{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('ls').read() }}` to check the directory content. The server return to this:

![](https://media.discordapp.net/attachments/961544480366931969/1432625481055866920/image.png?ex=6901bbf3&is=69006a73&hm=28934f12a925a73b3d8124bcf133b15bc79a29e77e990c27d115da5924349ccf&=&format=webp&quality=lossless&width=1774&height=493)

- Throughout this result, we can see the `flag` file, so we replace the `ls` command with `cat flag` to get the flag of this problem. 

**The flag is `picoCTF{s4rv3r_s1d3_t3mp14t3_1nj3ct10n5_4r3_c001_09365533}`**
