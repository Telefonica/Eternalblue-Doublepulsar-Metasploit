FROM debian:stretch

WORKDIR /root/Eternalblue-Doublepulsar-Metasploit

RUN apt-get update && \
	apt-get -y install wine git gnupg curl

RUN dpkg --add-architecture i386 && \ 
	apt-get update && \
	apt-get -y install wine32

RUN curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && \
  chmod 755 msfinstall && \
  ./msfinstall

ADD . /root/Eternalblue-Doublepulsar-Metasploit

RUN cp eternalblue_doublepulsar.rb /opt/metasploit-framework/embedded/framework/modules/exploits/windows/smb/

RUN mkdir -p /root/.wine/drive_c


