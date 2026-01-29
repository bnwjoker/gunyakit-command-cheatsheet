# Port 25 - SMTP

## Table of Contents
- [Enumeration](#enumeration)
    - [smtp-user-enum](#smtp-user-enum)

### Enumeration

#### smtp-user-enum

- Download smtp-user-enum script

```shell
git clone https://github.com/pentestmonkey/smtp-user-enum.git
cd smtp-user-enum
```

- Enumerate users โดยใช้ VRFY method

    - -M mode = Method ที่จะใช้สำหรับการตรวจสอบหา user โดยสามารถเลือกได้เป็น EXPN, VRFY หรือ RCPT (default: VRFY)

    ```shell
    ./smtp-user-enum.pl -M VRFY -u user -t
    ```

- Enumerate users โดยใช้ list

    ```shell
    ./smtp-user-enum.pl -M VRFY -U /usr/share/metasploit-framework/data/wordlists/unix_users.txt -t
    ```