# unpackme

### Information
* Category: RE
* Point:
* Level: Medium

### Description
The problem gives a binary file and we need to reverse it.

### Hint
What is UPX

### Solution
#### What we got ?
- We have a binary file packed by UPX tools. So we need to use `upx -d` command to unpack it.
- After decompressing, run the file and it gives us a question "What is my favourite number?". So I

#### How to get the flag ?
- After being unpacked, decompile it with IDA and check the `main`, we will found a hex value. We can convert it into a pseudocode like this:
    ``` pseudocode
    begin

        print "What's my favorite number? "

        input user_number   // read integer from user

        if user_number == 0x0B83CB then
            print "Correct!"
        else
            print "Wrong!"
        end if

    end
    ```
    
    ![hex]()

- Convert it into decimal value, we will get the correct answer of the question. Type it and get the flag.

    ![flag]()
