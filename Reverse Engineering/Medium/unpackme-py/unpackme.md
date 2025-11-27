# unpackme.py

### Information
* Category: RE
* Point:
* Level: Medium

### Description
The problem gives a python file and we need to reverse it.

### Hint
None

### Solution
#### What we got ?
- We have a python src code:
    ```python
    import base64
    from cryptography.fernet import Fernet



    payload = b'gAAAAABkzWGO_8MlYpNM0n0o718LL-w9m3rzXvCMRFghMRl6CSZwRD5DJOvN_jc8TFHmHmfiI8HWSu49MyoYKvb5mOGm_Jn4kkhC5fuRiGgmwEpxjh0z72dpi6TaPO2TorksAd2bNLemfTaYPf9qiTn_z9mvCQYV9cFKK9m1SqCSr4qDwHXgkQpm7IJAmtEJqyVUfteFLszyxv5-KXJin5BWf9aDPIskp4AztjsBH1_q9e5FIwIq48H7AaHmR8bdvjcW_ZrvhAIOInm1oM-8DjamKvhh7u3-lA=='

    key_str = 'correctstaplecorrectstaplecorrec'
    key_base64 = base64.b64encode(key_str.encode())
    f = Fernet(key_base64)
    plain = f.decrypt(payload)
    exec(plain.decode())
    ```

#### How to get the flag ?
- Change the code line `exec(plain.decode())` into `print(plain)` and run again the python file to get the flag.
    ```python
    import base64
    from cryptography.fernet import Fernet

    payload = b'gAAAAABkzWGO_8MlYpNM0n0o718LL-w9m3rzXvCMRFghMRl6CSZwRD5DJOvN_jc8TFHmHmfiI8HWSu49MyoYKvb5mOGm_Jn4kkhC5fuRiGgmwEpxjh0z72dpi6TaPO2TorksAd2bNLemfTaYPf9qiTn_z9mvCQYV9cFKK9m1SqCSr4qDwHXgkQpm7IJAmtEJqyVUfteFLszyxv5-KXJin5BWf9aDPIskp4AztjsBH1_q9e5FIwIq48H7AaHmR8bdvjcW_ZrvhAIOInm1oM-8DjamKvhh7u3-lA=='

    key_str = 'correctstaplecorrectstaplecorrec'
    key_base64 = base64.b64encode(key_str.encode())
    f = Fernet(key_base64)
    plain = f.decrypt(payload)
    print(plain.decode())
    ```
- Here is the result:
    ```command
    $ python3 pass.py

    pw = input('What\'s the password? ')

    if pw == 'batteryhorse':
    print('picoCTF{175_chr157m45_5274ff21}')
    else:
    print('That password is incorrect.')
    ```
