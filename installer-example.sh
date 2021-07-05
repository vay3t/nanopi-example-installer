#!/bin/bash

secret=arsenal
cd
mkdir $secret
cd $secret
echo -e "\n${YELLOW}[+] folder 'secret' created${NC}"

sudo sh -c 'echo "\nDefaults timestamp_timeout=-1">>/etc/sudoers'


sudo apt update && sudo apt dist-upgrade -y
sudo apt install autossh proxychains4 curl -y

sudo apt install -y \
	apache2 \
	arp-scan \
	dnsmasq \
	ettercap-text-only \
	git \
	hashcat \
	hexedit \
	hping3 \
	htop \
	macchanger \
	mariadb-client \
	mariadb-server \
	nbtscan \
	netcat \
	netdiscover \
	nmap \
	openvpn \
	php \
	prips \
	python3-dev \
	python3-pip \
	ruby-full \
	screen \
	smbclient \
	snapd \
	tcpdump \
	tmux \
	tor \
	torsocks \
	traceroute \
	tree \
	trickle \
	tshark \
	unrar \
	vim \
	wipe \
	whois;
  
sudo gem install \
	wpscan \
	bundle \
	evil-winrm \
	pedump;
  
sudo pip3 install \
	apkid \
	autopep8 \
	beautifulsoup4 \
	cloudscraper \
	diagrams \
	dnspython \
	dnstwist \
	exrex \
	fastapi \
	Faker \
	festin \
	getsploit \
	glances \
	grip \
	intensio-obfuscator \
	myjwt \
	name-that-hash \
	nfstream \
	nudepy \
	pipreqs \
	pproxy \
	proxy.py \
	pyautogui \
	pyinstaller \
	pyserv \
	python-telegram-bot \
	python-whois \
	requests \
	s3recon \
	scapy \
	search-that-hash \
	shadowsocks \
	shodan \
	slowloris \
	smtp-user-enum \
	sqlmap \
	ssh-mitm \
	sshuttle \
	wafw00f;
  
sudo snap install \
	amass \
	binwalk-spirotot \
	john-the-ripper \
	jwt-hack \
	lolcat \
	mycli \
  
sudo snap install go --classic
sudo snap install node --classic

git clone https://github.com/maurosoria/dirsearch
git clone https://github.com/lgandx/Responder
git clone https://github.com/drwetter/testssl.sh
git clone --recursive https://github.com/evgeni/qifi.git
git clone https://github.com/trustedsec/unicorn
git clone https://github.com/L-codes/Neo-reGeorg
git clone https://github.com/defparam/smuggler
git clone https://github.com/blackarrowsec/mssqlproxy
git clone https://github.com/volatilityfoundation/volatility3
git clone https://github.com/WHK102/htrash
git clone https://github.com/PowerShellMafia/PowerSploit
git clone https://github.com/samratashok/nishang
git clone https://github.com/danielbohannon/Invoke-Obfuscation
git clone https://github.com/nnposter/nndefaccts
git clone https://github.com/CISOfy/lynis
git clone https://github.com/s4vitar/rpcenum
git clone https://github.com/magnumripper/JohnTheRipper john
git clone https://github.com/cujanovic/Open-Redirect-Payloads
git clone https://github.com/trustedsec/hate_crack
git clone https://github.com/Mr-Un1k0d3r/DKMC
git clone https://github.com/cytopia/pwncat
git clone https://github.com/m4ll0k/Atlas
git clone https://github.com/OsandaMalith/IPObfuscator
git clone https://github.com/chrispetrou/EnumSNMP

sudo apt-get install gcc make git wget
git clone https://gitlab.com/akihe/radamsa.git && cd radamsa && make && sudo make install
cd && cd $secret

git clone https://github.com/trailofbits/onesixtyone
cd onesixtyone
make
sudo make install
cd && cd $secret

git clone https://github.com/decalage2/oletools
cd oletools
sudo python3 setup.py install
cd && cd $secret


sudo apt-get install -y libssl-dev libssh-dev libidn11-dev libpcre3-dev \
                 libgtk2.0-dev libmysqlclient-dev libpq-dev libsvn-dev \
                 firebird-dev libmemcached-dev libgpg-error-dev \
                 libgcrypt11-dev libgcrypt20-dev

git clone https://github.com/vanhauser-thc/thc-hydra
cd thc-hydra
./configure
make
sudo make install
cd && cd $secret

# metasploit
wget "https://apt.metasploit.com/$(curl -s https://apt.metasploit.com/ | grep 'arm64.deb' | tail -1 | cut -d '"' -f 2)"
sudo dpkg -i metasploit*.deb
rm metasploit*.deb
cd && cd $secret

sudo npm install -g yarn
sudo npm install -g elasticdump
#sudo npm install -g curlconverter
sudo npm install -g qrcode-terminal
sudo npm install -g s3rver
sudo npm install -g apk-mitm
sudo yarn global add wappalyzer

# snmpwn
git clone https://github.com/hatlord/snmpwn.git
cd snmpwn 
sudo bundle install
cd && cd $secret

# enum4linux-ng
git clone https://github.com/cddmp/enum4linux-ng
cd enum4linux-ng
sudo python3 setup.py install
cd && cd $secret

# Sherlock
git clone https://github.com/sherlock-project/sherlock.git
cd sherlock
python3 -m pip install -r requirements.txt
cd && cd $secret

# Photon
git clone https://github.com/s0md3v/Photon.git
cd Photon
sudo pip3 install -r requirements.txt
cd && cd $secret

# Impacket
git clone https://github.com/SecureAuthCorp/impacket
cd impacket
sudo python3 setup.py install
cd && cd $secret

# Sublist3r
git clone https://github.com/aboul3la/Sublist3r
cd Sublist3r
sudo pip3 install -r requirements.txt
cd && cd $secret

# spiderfoot
git clone https://github.com/smicallef/spiderfoot.git
cd spiderfoot
sudo pip3 install -r requirements.txt
cd && cd $secret

# theHarvester
git clone https://github.com/laramies/theHarvester
cd theHarvester
sudo pip3 install -r requirements.txt
cd && cd $secret

# git-dumper
git clone https://github.com/arthaud/git-dumper
cd git-dumper
sudo pip3 install -r requirements.txt
cd && cd $secret

# wesng
git clone https://github.com/bitsadmin/wesng
cd wesng
sudo python3 setup.py install
cd && cd $secret

# RsaCtfTool
git clone https://github.com/Ganapati/RsaCtfTool
cd RsaCtfTool
sudo apt-get install libgmp3-dev libmpc-dev -y
pip3 install -r requirements.txt
cd && cd $secret

# uncompyle6
git clone https://github.com/rocky/python-uncompyle6
cd python-uncompyle6
sudo python3 setup.py install
cd && cd $secret

# smbmap
git clone https://github.com/ShawnDEvans/smbmap
cd smbmap
python3 -m pip install -r requirements.txt
cd && cd $secret

# crowbar
git clone https://github.com/galkan/crowbar
cd crowbar/
pip3 install -r requirements.txt
cd && cd $secret

# SSRFmap
git clone https://github.com/swisskyrepo/SSRFmap
cd SSRFmap/
sudo pip3 install -r requirements.txt
cd && cd $secret

# s3viewer
git clone https://github.com/SharonBrizinov/s3viewer
cd s3viewer
python3 -m pip install -r packaging/requirements.txt
cd && cd $secret

# dotdotslash
git clone https://github.com/jcesarstef/dotdotslash
cd dotdotslash
sudo pip3 install -r requirements.txt
cd && cd $secret

# ntlm_theft
git clone https://github.com/Greenwolf/ntlm_theft
cd ntlm_theft
sudo pip3 install xlsxwriter
cd && cd $secret

# jwtcrack
git clone https://github.com/Sjord/jwtcrack
cd jwtcrack
sudo pip3 install -r requirements.txt
cd && cd $secret

# ccat
git clone https://github.com/cisco-config-analysis-tool/ccat
cd ccat
sudo pip3 install -r requirements.txt
cd && cd $secret

# wss
git clone https://github.com/WHK102/wss
cd wss
sudo pip3 install -r requirements.txt
cd && cd $secret

# fing
mkdir finggg
cd finggg
wget https://www.fing.com/images/uploads/general/CLI_Linux_Debian_5.5.2.zip
unzip CLI_Linux_Debian_5.5.2.zip
sudo dpkg -i fing-5.5.2-arm64.deb
cd ..
rm -rf finggg
cd && cd $secret

# searchsploit
sudo git clone https://github.com/offensive-security/exploitdb.git /opt/exploitdb
sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit

# cewl
echo -e "\n${YELLOW}[!] install cewl${NC}"
git clone https://github.com/digininja/CeWL
cd CeWL
bundle install
cd && cd $secret

# intruder payloads
git clone https://github.com/1N3/IntruderPayloads
cd IntruderPayloads
./install.sh
cd && cd $secret

echo -e "\n${YELLOW}[!] disable services${NC}"
sudo systemctl disable apache2
sudo systemctl disable bluetooth
sudo systemctl disable dnsmasq
sudo systemctl disable mariadb
sudo systemctl disable postgresql
sudo systemctl disable tor


sudo sed -i '$ d' /etc/sudoers
