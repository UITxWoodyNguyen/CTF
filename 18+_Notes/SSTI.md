# SSTI (Server - side Template Injection)

###### Sources of this note: [Link](https://www.cobalt.io/blog/a-pentesters-guide-to-server-side-template-injection-ssti)

## What is SSTI ?
- SSTI is is when an attacker is able to use native template syntax to inject a malicious payload into a template, which is then executed server-side.
- SSTI can occur when user input is concatenated directly into a template, rather than passed in as data. This allows attackers to inject arbitrary template directives in order to manipulate the template engine, often enabling them to take complete control of the server. 
- SSTI payloads are delivered and evaluated server-side, potentially making them much more dangerous than a typical client-side template injection.

> *Vietnamese version:*
    > - SSTI là khi một kẻ tấn công có thể sử dụng cú pháp template gốc để chèn một payload độc hại vào template, và payload đó sau đó được thực thi ở phía máy chủ.
    > - SSTI có thể xảy ra khi dữ liệu do người dùng cung cấp bị nối trực tiếp vào template thay vì được truyền vào như dữ liệu. Điều này cho phép kẻ tấn công chèn các chỉ thị (directive) template tùy ý để thao túng engine template, thường khiến họ có thể chiếm quyền điều khiển hoàn toàn máy chủ.
    > - Payload của SSTI được gửi và đánh giá ở phía máy chủ, do đó có thể nguy hiểm hơn nhiều so với lỗ hổng chèn template phía client thông thường.

## How does it work?
- For the sake of simplicity, imagine you're testing the parameter of the following request:
``` apache
POST /some-endpoint HTTP/1.1
Host: vulnerable-website.com
parameter=value
```
- To detect the vulnerability, use the polyglot payload as the value of the parameter which is a sequence of special characters such as the following:
``` apache
POST /some-endpoint HTTP/1.1
Host: vulnerable-website.com
parameter=$
```

## SSTI Impact
- The impact of server-side template injection vulnerabilities is generally critical, resulting in remote code execution by taking full control of the back-end server. Even without the code execution, the attacker may be able to read sensitive data on the server. There are also rare cases where an SSTI vulnerability is not critical, depending on the template engine.

> *Vietnamese version:*
    > - Tác động của lỗ hổng chèn template phía máy chủ (SSTI) thường ở mức nghiêm trọng, có thể dẫn đến thực thi mã từ xa (remote code execution) và cho phép kẻ tấn công chiếm toàn quyền kiểm soát máy chủ back-end. Ngay cả khi không thể thực thi mã, kẻ tấn công vẫn có thể đọc được dữ liệu nhạy cảm trên máy chủ. Trong một số trường hợp hiếm hoi, mức độ nghiêm trọng của lỗ hổng SSTI có thể không cao, tuỳ thuộc vào loại engine template được sử dụng.

## How to SSTI?
- To identify SSTI vulnerabilities, use a Polyglot payload composed of special characters commonly used in template expressions to fuzz the template.
```apache
    ${{<%[%'"}}%\.
```
- In case of a vulnerability, an error message can be returned or the exception can be raised by the server. This can be used to identify the vulnerability and the template engine in use.

- To identify the vulnerability, the following to-do list can be followed:
    - Detect where the template injection exist
    - Identify the template engine and validate the vulnerability
    - Follow the manuals for the specific template engine
    - Exploit the vulnerability
- The following cheat sheet can be used to identify the template engine in use:
    ![](https://www.cobalt.io/hubfs/0_pJf0zn5ChHY9X8sF-1-png-1.png)

## Automated Tools
- Read more about [Tplmap](https://github.com/epinna/tplmap)

## Cheatsheet
![](https://www.cobalt.io/hs-fs/hubfs/Pentester%E2%80%99s%20Guide%20to%20Server%20Side%20Template%20Injection%20(SSTI)%201%20of%204.png?width=1460&name=Pentester%E2%80%99s%20Guide%20to%20Server%20Side%20Template%20Injection%20(SSTI)%201%20of%204.png)

![](https://www.cobalt.io/hs-fs/hubfs/Pentester%E2%80%99s%20Guide%20to%20Server%20Side%20Template%20Injection%20(SSTI)%202%20of%204.png?width=1412&name=Pentester%E2%80%99s%20Guide%20to%20Server%20Side%20Template%20Injection%20(SSTI)%202%20of%204.png)

![](https://www.cobalt.io/hs-fs/hubfs/Pentester%E2%80%99s%20Guide%20to%20Server%20Side%20Template%20Injection%20(SSTI)%203%20of%204.png?width=1341&name=Pentester%E2%80%99s%20Guide%20to%20Server%20Side%20Template%20Injection%20(SSTI)%203%20of%204.png)

![](https://www.cobalt.io/hs-fs/hubfs/Pentester%E2%80%99s%20Guide%20to%20Server%20Side%20Template%20Injection%20(SSTI)%204%20of%204.png?width=1376&name=Pentester%E2%80%99s%20Guide%20to%20Server%20Side%20Template%20Injection%20(SSTI)%204%20of%204.png)
