Searchscan
==========
Both Nmap and Metasploit are constantly adding new scanning capabilities. In addition, developers routinely create custom NSE scripts as well. Searchscan can help you find the script you need to scan what you want. Searchscan will search the local machine for installed Nmap NSE and MSF Auxiliary scripts. In addition, it will search GitHub for Nmap NSE scripts.

Usage
-----
    ./searchscan [options] keyword
      -c	Build the GitHub cache.
      -d	Show description along with name and path.
      -n	Search for keyword in the name only.

Examples
--------
./searchscan ms17

    smb-vuln-ms17-010.nse - /usr/share/nmap/scripts/smb-vuln-ms17-010.nse
    smb_ms17_010.rb - /usr/share/metasploit-framework/modules/auxiliary/scanner/smb/smb_ms17_010.rb

./searchscan -d ms17

    smb-vuln-ms17-010.nse
    =====================
    Path: /usr/share/nmap/scripts/smb-vuln-ms17-010.nse

    Attempts to detect if a Microsoft SMBv1 server is vulnerable to a remote code
    execution vulnerability (ms17-010, a.k.a. EternalBlue). The vulnerability is
    actively exploited by WannaCry and Petya ransomware and other malware.

    The script connects to the $IPC tree, executes a transaction on FID 0 and
    checks if the error "STATUS_INSUFF_SERVER_RESOURCES" is returned to determine
    if the target is not patched against ms17-010. Additionally it checks for
    known error codes returned by patched systems.

    Tested on Windows XP, 2003, 7, 8, 8.1, 10, 2008, 2012 and 2016.

    References:
     * https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
     * https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
     * https://msdn.microsoft.com/en-us/library/ee441489.aspx
     * https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/scanner/smb/smb_ms17_010.rb
     * https://github.com/cldrn/nmap-nse-scripts/wiki/Notes-about-smb-vuln-ms17-010


    smb_ms17_010.rb
    ===============
    Path: /usr/share/metasploit-framework/modules/auxiliary/scanner/smb/smb_ms17_010.rb

    Uses information disclosure to determine if MS17-010 has been patched or not.
    Specifically, it connects to the IPC$ tree and attempts a transaction on FID
    0. If the status returned is "STATUS_INSUFF_SERVER_RESOURCES", the machine
    does not have the MS17-010 patch. If the machine is missing the MS17-010
    patch, the module will check for an existing DoublePulsar (ring 0
    shellcode/malware) infection. This module does not require valid SMB
    credentials in default server configurations. It can log on as the user "\"
    and connect to IPC$.

Configuration
-------------
    Searchscan reads and parses the Nmap NSE and Metasploit scripts that are installed locally on the machine. Searchscan was designed to run on Kali Linux. If you are running Searchscan on any other OS you will need to ensure Nmap and Metasploit are installed and you will need to modify the `config.nsePath` and `config.msfauxPath` variables in the main.go file.

    If you want to search GitHub, you will need to build the local cache using `./searchscan -c`. Before you can build the cache you will need to modify the `config.username`, `config.apitoken`, and `config.cachePath` variables in the main.go file. Once the cache is built you can update it periodically by running `./searchscan -c`.

    If you need to create an access token, follow the directions at https://help.github.com/articles/creating-a-personal-access-token-for-the-command-line/. The access token only needs the default permissions.

Building
--------
Building Searchscan is easy and follows a similar pattern to most Golang scripts.

    git clone https://
    cd
    go build
    ./searchscan

To Do
-----
Add support for MSF Aux modules on GitHub, if possible.
