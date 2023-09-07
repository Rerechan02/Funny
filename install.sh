#!/bin/bash
run_eula() {
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1
sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1
#warna
export LANG='en_US.UTF-8'
export LANGUAGE='en_US.UTF-8'
# // Export Color & Information
export RED='\033[0;31m'
export GREEN='\033[0;32m'
export YELLOW='\033[0;33m'
export BLUE='\033[0;34m'
export PURPLE='\033[0;35m'
export CYAN='\033[0;36m'
export LIGHT='\033[0;37m'
export NC='\033[0m'
BIRed='\033[1;91m'
red='\e[1;31m'
bo='\e[1m'
red='\e[1;31m'
green='\e[0;32m'
yell='\e[1;33m'
tyblue='\e[1;36m'
purple() { echo -e "\\033[35;1m${*}\\033[0m"; }
tyblue() { echo -e "\\033[36;1m${*}\\033[0m"; }
yellow() { echo -e "\\033[33;1m${*}\\033[0m"; }
green() { echo -e "\\033[32;1m${*}\\033[0m"; }
red() { echo -e "\\033[31;1m${*}\\033[0m"; }
# // Export Banner Status Information
export EROR="[${RED} ERROR ${NC}]"
export INFO="[${YELLOW} INFO ${NC}]"
export OKEY="[${GREEN} OKEY ${NC}]"
export PENDING="[${YELLOW} PENDING ${NC}]"
export SEND="[${YELLOW} SEND ${NC}]"
export RECEIVE="[${YELLOW} RECEIVE ${NC}]"
# // Export Align
export BOLD="\e[1m"
export WARNING="${RED}\e[5m"
export UNDERLINE="\e[4m"
clear
echo -e "${tyblue} Welcome To FunnyVPN AutoScript......${NC} "
sleep 2
echo -e "[ ${green}INFO${NC} ] Preparing the install file"
apt install git curl -y >/dev/null 2>&1
echo -e "[ ${green}INFO${NC} ] installation file is ready"
sleep 2
sleep 3
clear
echo -e "${GREEN}Starting Installation............${NC}"
sleep 1
clear
rm -fr *.sh
}
DATE2=$(date -R | cut -d " " -f -5)
# > install gotop
gotop_latest="$(curl -s https://api.github.com/repos/xxxserxxx/gotop/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
gotop_link="https://github.com/xxxserxxx/gotop/releases/download/v$gotop_latest/gotop_v"$gotop_latest"_linux_amd64.deb"
curl -sL "$gotop_link" -o /tmp/gotop.deb
dpkg -i /tmp/gotop.deb >/dev/null 2>&1
apt install zip -y
apt install unzip -y
apt install curl -y
# BOT INFORMATION
export CHATID="6389176425"
export KEY="6230907878:AAExag4j8lRsJbMdAIv6T9STI1g6kp_Vq68"
export TIME="10"
export URL="https://api.telegram.org/bot$KEY/sendMessage"
IP=$(curl ifconfig.me);
domain=$(cat /etc/xray/domain)
date=$(date +"%Y-%m-%d")

run_izin() {
apt install curl -y
#link izin ip vps
url_izin='https://raw.githubusercontent.com/Rerechan02/iziznscript/main/ip'

# Mendapatkan IP VPS saat ini
ip_vps=$(curl -s ifconfig.me)

# Mendapatkan isi file izin.txt dari URL
izin=$(curl -s "$url_izin")

# Memeriksa apakah konten izin.txt berhasil didapatkan
if [[ -n "$izin" ]]; then
  while IFS= read -r line; do
    # Memisahkan nama VPS, IP VPS, dan tanggal kadaluwarsa
    nama=$(echo "$line" | awk '{print $1}')
    ipvps=$(echo "$line" | awk '{print $2}')
    tanggal=$(echo "$line" | awk '{print $3}')

    # Memeriksa apakah IP VPS saat ini cocok dengan IP VPS yang ada di izin.txt
    if [[ "$ipvps" == "$ip_vps" ]]; then
      echo "Nama VPS: $nama"
      echo "IP VPS: $ipvps"
      echo "Tanggal Kadaluwarsa: $tanggal"
      break
    fi
  done <<< "$izin"

  # Memeriksa apakah IP VPS ditemukan dalam izin.txt
  if [[ "$ipvps" != "$ip_vps" ]]; then
    echo "IP VPS tidak ditemukan dalam izin.txt"
    exit 0
  fi
else
  echo "Konten izin.txt tidak berhasil didapatkan dari URL"
  exit 0
fi
clear
}
clear
green='\e[0;32m'
yell='\e[1;33m'
tyblue='\e[1;36m'
clear
echo -e "${tyblue} Welcome To FunnyVPN AutoScript......${NC} "
sleep 2
echo -e "[ ${green}INFO${NC} ] Preparing the install file"
apt install git curl -y >/dev/null 2>&1
echo -e "[ ${green}INFO${NC} ] installation file is ready"
sleep 2
sleep 3
clear
echo -e "${GREEN}Starting Installation............${NC}"
sleep 1
clear
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1
sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1
apt update
apt install sshpass -y
version='1.0'
ipip=$(curl ipinfo.io/ip)
clear
run_bot() {
id="5662244939"
bot="5308760844:AAHTrXQD4Awu5WkTqAAiv8tzIjrlxT0OF7U"
MESSAGE="$1"
curl -s --data "text=$MESSAGE" --data "chat_id=$id" 'https://api.telegram.org/bot'$bot'/sendMessage' > /dev/null &
}

run_input() {
clear
version="1.0"
read -p "Input Domain : " domain
}

run_update() {
apt update -y
apt upgrade -y
apt install ruby nload gawk htop bc iftop -y
apt install iptables sudo net-tools neofetch socat curl wget htop vnstat uuid screen -y
apt-get install build-essential zlib1g-dev libpcre3 libpcre3-dev unzip -y
apt-get install libcurl4-openssl-dev libssl-dev libjansson-dev automake autotools-dev build-essential gcc make cmake -y
apt install iptables iptables-persistent -y
apt install curl socat xz-utils wget apt-transport-https gnupg gnupg2 gnupg1 dnsutils lsb-release -y
apt install socat cron bash-completion ntpdate -y
gem install lolcat
apt install software-properties-common -y
apt install certbot python python2 -y
}

run_iptables() {
iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 80 -j ACCEPT
iptables -I INPUT -m state --state NEW -m udp -p udp --dport 80 -j ACCEPT
iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 443 -j ACCEPT
iptables -I INPUT -m state --state NEW -m udp -p udp --dport 443 -j ACCEPT
iptables-save > /etc/iptables.up.rules
iptables-restore -t < /etc/iptables.up.rules
netfilter-persistent save
netfilter-persistent reload
}

run_bahan() {
#mkdir folder
mkdir /etc/xray
mkdir /etc/funny
mkdir /etc/funny/limit
mkdir /etc/funny/limit/trojan
mkdir /etc/funny/limit/vless
mkdir /etc/funny/limit/vmess
mkdir /etc/funny/limit/ssh
mkdir /etc/funny/limit/ssh/ip
mkdir /etc/funny/limit/trojan/ip
mkdir /etc/funny/limit/trojan/quota
mkdir /etc/funny/limit/vless/ip
mkdir /etc/funny/limit/vless/quota
mkdir /etc/funny/limit/vmess/ip
mkdir /etc/funny/limit/vmess/quota
mkdir /etc/funny/trojan
mkdir /etc/funny/vless
mkdir /etc/funny/vmess
mkdir /etc/funny/log
mkdir /etc/funny/log/trojan
mkdir /etc/funny/log/vless
mkdir /etc/funny/log/vmess
mkdir /etc/funny/log/ssh
mkdir /etc/funny/cache
mkdir /etc/funny/cache/trojan-tcp
mkdir /etc/funny/cache/trojan-ws
mkdir /etc/funny/cache/trojan-grpc
mkdir /etc/funny/cache/vless-ws
mkdir /etc/funny/cache/vless-grpc
mkdir /etc/funny/cache/vmess-ws
mkdir /etc/funny/cache/vmess-grpc
mkdir /etc/funny/cache/vmess-ws-orbit
mkdir /etc/funny/cache/vmess-ws-orbit1
echo $domain >> /etc/xray/domain
curl ipinfo.io/org | cut -d ' ' -f 2-10 > /root/.myisp
curl ipinfo.io/city > /root/.mycity
curl ipinfo.io/ip > /root/.myip
echo -e "$version" > /root/.version
}

run_ssh() {
#instal sslh
#!/bin/bash
# Install SSLH
apt -y install sslh
rm -f /etc/default/sslh
rm -fr /usr/sbin/sslh
wget -O /usr/sbin/sslh https://raw.githubusercontent.com/Rerechan02/fn/main/sslh
chmod +x /usr/sbin/sslh
# Settings SSLH
cat> /etc/default/sslh << END
# Default options for sslh initscript
# sourced by /etc/init.d/sslh

# Disabled by default, to force yourself
# to read the configuration:
# - /usr/share/doc/sslh/README.Debian (quick start)
# - /usr/share/doc/sslh/README, at "Configuration" section
# - sslh(8) via "man sslh" for more configuration details.
# Once configuration ready, you *must* set RUN to yes here
# and try to start sslh (standalone mode only)

RUN=yes

# binary to use: forked (sslh) or single-thread (sslh-select) version
# systemd users: don't forget to modify /lib/systemd/system/sslh.service
DAEMON=/usr/sbin/sslh

DAEMON_OPTS="--user sslh --listen 0.0.0.0:8000 --ssh 127.0.0.1:111 --http 127.0.0.1:700 --pidfile /var/run/sslh/sslh.pid -n"

END

# Restart Service SSLH
service sslh restart
systemctl restart sslh
systemctl enable sslh
##end
apt install dropbear
rm /etc/default/dropbear
rm /etc/issue.net
cat>  /etc/default/dropbear << END
# disabled because OpenSSH is installed
# change to NO_START=0 to enable Dropbear
NO_START=0
# the TCP port that Dropbear listens on
DROPBEAR_PORT=111

# any additional arguments for Dropbear
#DROPBEAR_EXTRA_ARGS="-p 109 -p 69 "

# specify an optional banner file containing a message to be
# sent to clients before they connect, such as "/etc/issue.net"
DROPBEAR_BANNER="/etc/issue.net"

# RSA hostkey file (default: /etc/dropbear/dropbear_rsa_host_key)
#DROPBEAR_RSAKEY="/etc/dropbear/dropbear_rsa_host_key"

# DSS hostkey file (default: /etc/dropbear/dropbear_dss_host_key)
#DROPBEAR_DSSKEY="/etc/dropbear/dropbear_dss_host_key"

# ECDSA hostkey file (default: /etc/dropbear/dropbear_ecdsa_host_key)
#DROPBEAR_ECDSAKEY="/etc/dropbear/dropbear_ecdsa_host_key"

# Receive window size - this is a tradeoff between memory and
# network performance
DROPBEAR_RECEIVE_WINDOW=65536
END
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells
/etc/init.d/dropbear restart
cat> /etc/issue.net << END
<br><font color="blue"><b>===============================</br></font><br>
<font color="red"><b>********  Funny VPN  ********</b></font><br>
<font color="blue"><b>===============================</br></font><br>
END
#ws-stunnel
wget -O /usr/local/bin/ws-stunnel https://raw.githubusercontent.com/Rerechan02/fn/main/ws-stunnel
# install badvpn
cd
clear
wget https://github.com/NevermoreSSH/VVV/raw/main/badvpn/setup.sh && chmod +x * && ./setup.sh
rm -fr setup.sh
clear
}

run_port_ssh() {
#!/bin/bash
echo "Port 22" >> /etc/ssh/sshd_config
nowww=$(cat /etc/ssh/sshd_config | grep "Port 22")
sed -i "s/$nowww/Port 3303/g" /etc/ssh/sshd_config
}

run_nginx() {
sudo apt install gnupg2 ca-certificates lsb-release -y
fiyaku=$(lsb_release -a | sed -n 1p | cut -f 2 | tr A-Z a-z)
echo "deb http://nginx.org/packages/mainline/$fiyaku $(lsb_release -cs) nginx" | sudo tee /etc/apt/sources.list.d/nginx.list
echo -e "Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n" | sudo tee /etc/apt/preferences.d/99nginx
curl -o /tmp/nginx_signing.key https://nginx.org/keys/nginx_signing.key
# gpg --dry-run --quiet --import --import-options import-show /tmp/nginx_signing.key
sudo mv /tmp/nginx_signing.key /etc/apt/trusted.gpg.d/nginx_signing.asc
sudo apt update
apt install nginx -y
rm /etc/nginx/conf.d/*.conf
rm /etc/nginx/nginx.conf
cd /etc/nginx
wget https://raw.githubusercontent.com/nuralfiya/Autorekonek-Libernet/main/nginx.conf
curl https://raw.githubusercontent.com/Rerechan02/Funny/main/funny.conf > /etc/nginx/conf.d/funny.conf
sed -i "s/xxx/$domain/g" /etc/nginx/conf.d/funny.conf
cd
sysemctl restart nginx
}

run_bbr() {
echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
sysctl -p
}

run_xray() {
# // VERSION XRAY
export version="$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"

# // INSTALL CORE XRAY
cd /usr/local/bin
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version ${version}
#wget https://github.com/dharak36/Xray-core/releases/download/v1.0.0/xray.linux.64bit
#rm /usr/local/bin/xray
#mv xray.linux.64bit /usr/local/bin/xray
chmod +x /usr/local/bin/xray
cd
}

run_json() {
cat> /etc/xray/trojan-tcp.json << END
{
  "log": {
      "access": "/var/log/xray/trojan.log",
      "loglevel": "info"
  },
  "inbounds": [
     {
      "listen": "127.0.0.1",
      "port": 10085,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1"
      },
      "tag": "api"
    },
    {
      "port": 443,
      "protocol": "trojan",
      "tag": "TROJANTCP",
      "settings": {
        "clients": [
          {
            "password": "$(uuid)",
            "flow": "xtls-rprx-direct",
            "email": "testngab"
#xray
          }
        ],
        "decryption": "none",
        "fallbacks": [
          {
            "alpn": "h2",
            "dest": 31302,
            "xver": 0
          },
          {
            "dest": 8000,
            "xver": 1
          },
          {
            "path": "/vmessws",
            "dest": 31298,
            "xver": 1
          },
          {
            "path": "/vlessws",
            "dest": 31297,
            "xver": 1
          },
          {
            "path": "/trojanws",
            "dest": 60002,
            "xver": 1
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "xtls",
        "xtlsSettings": {
          "minVersion": "1.2",
          "certificates": [
            {
              "certificateFile": "/etc/xray/xray.crt",
              "keyFile": "/etc/xray/xray.key",
              "ocspStapling": 3600,
              "usage": "encipherment"
            }
          ]
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": [
          "0.0.0.0/8",
          "10.0.0.0/8",
          "100.64.0.0/10",
          "169.254.0.0/16",
          "172.16.0.0/12",
          "192.0.0.0/24",
          "192.0.2.0/24",
          "192.168.0.0/16",
          "198.18.0.0/15",
          "198.51.100.0/24",
          "203.0.113.0/24",
          "::1/128",
          "fc00::/7",
          "fe80::/10"
        ],
        "outboundTag": "blocked"
      },
      {
        "inboundTag": [
          "api"
        ],
        "outboundTag": "api",
        "type": "field"
      },
      {
        "type": "field",
        "outboundTag": "blocked",
        "protocol": [
          "bittorrent"
        ]
      }
    ]
  },
  "stats": {},
  "api": {
    "services": [
      "StatsService"
    ],
    "tag": "api"
  },
  "policy": {
    "levels": {
      "0": {
        "statsUserDownlink": true,
        "statsUserUplink": true
      }
    },
    "system": {
      "statsInboundUplink": true,
      "statsInboundDownlink": true,
      "statsOutboundUplink" : true,
      "statsOutboundDownlink" : true
    }
  }
}
END
#create trojan-ws
cat> /etc/xray/trojan-ws.json << END
{
   "log": {
      "access": "/var/log/xray/trojan.log",
      "loglevel": "info"
  },
 "inbounds": [
     {
      "listen": "127.0.0.1",
      "port": 10001,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1"
      },
      "tag": "api"
    },
    {
      "port": 60002,
      "listen": "127.0.0.1",
      "protocol": "trojan",
      "tag": "trojanWS",
      "settings": {
        "clients": [
          {
            "password": "$(uuid)"
#xray
          }
        ],
        "fallbacks": [
          {
            "dest": "81"
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "acceptProxyProtocol": true,
          "path": "/trojanws"
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": [
          "0.0.0.0/8",
          "10.0.0.0/8",
          "100.64.0.0/10",
          "169.254.0.0/16",
          "172.16.0.0/12",
          "192.0.0.0/24",
          "192.0.2.0/24",
          "192.168.0.0/16",
          "198.18.0.0/15",
          "198.51.100.0/24",
          "203.0.113.0/24",
          "::1/128",
          "fc00::/7",
          "fe80::/10"
        ],
        "outboundTag": "blocked"
      },
      {
        "inboundTag": [
          "api"
        ],
        "outboundTag": "api",
        "type": "field"
      },
      {
        "type": "field",
        "outboundTag": "blocked",
        "protocol": [
          "bittorrent"
        ]
      }
    ]
  },
  "stats": {},
  "api": {
    "services": [
      "StatsService"
    ],
    "tag": "api"
  },
  "policy": {
    "levels": {
      "0": {
        "statsUserDownlink": true,
        "statsUserUplink": true
      }
    },
    "system": {
      "statsInboundUplink": true,
      "statsInboundDownlink": true,
      "statsOutboundUplink" : true,
      "statsOutboundDownlink" : true
    }
  }
}
END
#create vless-ws
cat> /etc/xray/vless-ws.json << END
{
  "log": {
      "access": "/var/log/xray/vless.log",
      "loglevel": "info"
  },
  "inbounds": [
     {
      "listen": "127.0.0.1",
      "port": 10003,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1"
      },
      "tag": "api"
    },
    {
      "port": 31297,
      "listen": "127.0.0.1",
      "protocol": "vless",
      "tag": "VLESSWS",
      "settings": {
        "clients": [
          {
            "id": "$(uuid)"
#xray
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "acceptProxyProtocol": true,
          "path": "/vlessws"
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": [
          "0.0.0.0/8",
          "10.0.0.0/8",
          "100.64.0.0/10",
          "169.254.0.0/16",
          "172.16.0.0/12",
          "192.0.0.0/24",
          "192.0.2.0/24",
          "192.168.0.0/16",
          "198.18.0.0/15",
          "198.51.100.0/24",
          "203.0.113.0/24",
          "::1/128",
          "fc00::/7",
          "fe80::/10"
        ],
        "outboundTag": "blocked"
      },
      {
        "inboundTag": [
          "api"
        ],
        "outboundTag": "api",
        "type": "field"
      },
      {
        "type": "field",
        "outboundTag": "blocked",
        "protocol": [
          "bittorrent"
        ]
      }
    ]
  },
  "stats": {},
  "api": {
    "services": [
      "StatsService"
    ],
    "tag": "api"
  },
  "policy": {
    "levels": {
      "0": {
        "statsUserDownlink": true,
        "statsUserUplink": true
      }
    },
    "system": {
      "statsInboundUplink": true,
      "statsInboundDownlink": true,
      "statsOutboundUplink" : true,
      "statsOutboundDownlink" : true
    }
  }
}
END
#create vless-ws
cat> /etc/xray/vmess-ws.json << END
{
  "log": {
      "access": "/var/log/xray/vmess.log",
      "loglevel": "info"
  },
  "inbounds": [
     {
      "listen": "127.0.0.1",
      "port": 10005,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1"
      },
      "tag": "api"
    },
    {
      "listen": "127.0.0.1",
      "port": 31298,
      "protocol": "vmess",
      "tag": "VMessWS",
      "settings": {
        "clients": [
          {
            "id": "$(uuid)"
#xray
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "acceptProxyProtocol": true,
          "path": "/vmessws"
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": [
          "0.0.0.0/8",
          "10.0.0.0/8",
          "100.64.0.0/10",
          "169.254.0.0/16",
          "172.16.0.0/12",
          "192.0.0.0/24",
          "192.0.2.0/24",
          "192.168.0.0/16",
          "198.18.0.0/15",
          "198.51.100.0/24",
          "203.0.113.0/24",
          "::1/128",
          "fc00::/7",
          "fe80::/10"
        ],
        "outboundTag": "blocked"
      },
      {
        "inboundTag": [
          "api"
        ],
        "outboundTag": "api",
        "type": "field"
      },
      {
        "type": "field",
        "outboundTag": "blocked",
        "protocol": [
          "bittorrent"
        ]
      }
    ]
  },
  "stats": {},
  "api": {
    "services": [
      "StatsService"
    ],
    "tag": "api"
  },
  "policy": {
    "levels": {
      "0": {
        "statsUserDownlink": true,
        "statsUserUplink": true
      }
    },
    "system": {
      "statsInboundUplink": true,
      "statsInboundDownlink": true,
      "statsOutboundUplink" : true,
      "statsOutboundDownlink" : true
    }
  }
}
END
#jdjd
cat> /etc/xray/vmess-ws-orbit.json << END
{
  "log": {
      "access": "/var/log/xray/vmess.log",
      "loglevel": "info"
  },
  "inbounds": [
     {
      "listen": "127.0.0.1",
      "port": 10011,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1"
      },
      "tag": "api"
    },
    {
      "listen": "127.0.0.1",
      "port": 30301,
      "protocol": "vmess",
      "tag": "VMessWS",
      "settings": {
        "clients": [
          {
            "id": "$(uuid)"
#xray
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "acceptProxyProtocol": true,
          "path": "/kuota-habis"
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": [
          "0.0.0.0/8",
          "10.0.0.0/8",
          "100.64.0.0/10",
          "169.254.0.0/16",
          "172.16.0.0/12",
          "192.0.0.0/24",
          "192.0.2.0/24",
          "192.168.0.0/16",
          "198.18.0.0/15",
          "198.51.100.0/24",
          "203.0.113.0/24",
          "::1/128",
          "fc00::/7",
          "fe80::/10"
        ],
        "outboundTag": "blocked"
      },
      {
        "inboundTag": [
          "api"
        ],
        "outboundTag": "api",
        "type": "field"
      },
      {
        "type": "field",
        "outboundTag": "blocked",
        "protocol": [
          "bittorrent"
        ]
      }
    ]
  },
  "stats": {},
  "api": {
    "services": [
      "StatsService"
    ],
    "tag": "api"
  },
  "policy": {
    "levels": {
      "0": {
        "statsUserDownlink": true,
        "statsUserUplink": true
      }
    },
    "system": {
      "statsInboundUplink": true,
      "statsInboundDownlink": true,
      "statsOutboundUplink" : true,
      "statsOutboundDownlink" : true
    }
  }
}
END
#777
cat> /etc/xray/vmess-ws-orbit1.json << END
{
  "log": {
      "access": "/var/log/xray/vmess.log",
      "loglevel": "info"
  },
  "inbounds": [
     {
      "listen": "127.0.0.1",
      "port": 10012,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1"
      },
      "tag": "api"
    },
    {
      "listen": "127.0.0.1",
      "port": 30302,
      "protocol": "vmess",
      "tag": "VMessWS",
      "settings": {
        "clients": [
          {
            "id": "$(uuid)"
#xray
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "acceptProxyProtocol": true,
          "path": "/worryfree"
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": [
          "0.0.0.0/8",
          "10.0.0.0/8",
          "100.64.0.0/10",
          "169.254.0.0/16",
          "172.16.0.0/12",
          "192.0.0.0/24",
          "192.0.2.0/24",
          "192.168.0.0/16",
          "198.18.0.0/15",
          "198.51.100.0/24",
          "203.0.113.0/24",
          "::1/128",
          "fc00::/7",
          "fe80::/10"
        ],
        "outboundTag": "blocked"
      },
      {
        "inboundTag": [
          "api"
        ],
        "outboundTag": "api",
        "type": "field"
      },
      {
        "type": "field",
        "outboundTag": "blocked",
        "protocol": [
          "bittorrent"
        ]
      }
    ]
  },
  "stats": {},
  "api": {
    "services": [
      "StatsService"
    ],
    "tag": "api"
  },
  "policy": {
    "levels": {
      "0": {
        "statsUserDownlink": true,
        "statsUserUplink": true
      }
    },
    "system": {
      "statsInboundUplink": true,
      "statsInboundDownlink": true,
      "statsOutboundUplink" : true,
      "statsOutboundDownlink" : true
    }
  }
}
END
#create trojan-grpc
cat> /etc/xray/trojan-grpc.json << END
{
   "log": {
      "access": "/var/log/xray/trojan.log",
      "loglevel": "info"
  },
 "inbounds": [
     {
      "listen": "127.0.0.1",
      "port": 10002,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1"
      },
      "tag": "api"
    },
    {
      "port": 31304,
      "listen": "127.0.0.1",
      "protocol": "trojan",
      "tag": "trojanGRPC",
      "settings": {
        "clients": [
          {
            "password": "$(uuid)"
#xray
          }
        ],
        "fallbacks": [
          {
            "dest": "81"
          }
        ]
      },
      "streamSettings": {
        "network": "grpc",
        "security": "none",
        "grpcSettings": {
          "serviceName": "trojan-grpc",
          "multiMode": true,
          "acceptProxyProtocol": true
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": [
          "0.0.0.0/8",
          "10.0.0.0/8",
          "100.64.0.0/10",
          "169.254.0.0/16",
          "172.16.0.0/12",
          "192.0.0.0/24",
          "192.0.2.0/24",
          "192.168.0.0/16",
          "198.18.0.0/15",
          "198.51.100.0/24",
          "203.0.113.0/24",
          "::1/128",
          "fc00::/7",
          "fe80::/10"
        ],
        "outboundTag": "blocked"
      },
      {
        "inboundTag": [
          "api"
        ],
        "outboundTag": "api",
        "type": "field"
      },
      {
        "type": "field",
        "outboundTag": "blocked",
        "protocol": [
          "bittorrent"
        ]
      }
    ]
  },
  "stats": {},
  "api": {
    "services": [
      "StatsService"
    ],
    "tag": "api"
  },
  "policy": {
    "levels": {
      "0": {
        "statsUserDownlink": true,
        "statsUserUplink": true
      }
    },
    "system": {
      "statsInboundUplink": true,
      "statsInboundDownlink": true,
      "statsOutboundUplink" : true,
      "statsOutboundDownlink" : true
    }
  }
}
END
#create ntls
cat> /etc/xray/ntls.json << END
{
  "log": {
      "access": "/var/log/xray/trojan.log",
      "loglevel": "info"
  },
  "inbounds": [
    {
      "port": 80,
      "protocol": "trojan",
      "tag": "TROJANTCP",
      "settings": {
        "clients": [
          {
            "password": "eef46d87-ae46-d801-e0d4-6c87ae46d801",
            "flow": "xtls-rprx-direct",
            "email": "trojan.ket-yt.xyz_VLESS_XTLS/TLS-direct_TCP"
          }
        ],
        "decryption": "none",
        "fallbacks": [
          {
            "dest": 8000,
            "xver": 1
          },
          {
            "path": "/kuota-habis",
            "dest": 30301,
            "xver": 1
          },
          {
            "path": "/worryfree",
            "dest": 30302,
            "xver": 1
          },
          {
            "path": "/vmessws",
            "dest": 31298,
            "xver": 1
          },
          {
            "path": "/vlessws",
            "dest": 31297,
            "xver": 1
          },
          {
            "path": "/trojanws",
            "dest": 60002,
            "xver": 1
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "none"
      }
    }
  ],
  "outbounds": [
      {
          "protocol": "freedom",
          "tag": "direct"
      }
  ]
}
END
#jdjdj
cat> /etc/xray/ntls-8080.json << END
{
  "log": {
      "access": "/var/log/xray/trojan.log",
      "loglevel": "info"
  },
  "inbounds": [
    {
      "port": 8080,
      "protocol": "trojan",
      "tag": "TROJANTCP",
      "settings": {
        "clients": [
          {
            "password": "$(uuid)",
            "flow": "xtls-rprx-direct",
            "email": "trojan.ket-yt.xyz_VLESS_XTLS/TLS-direct_TCP"
          }
        ],
        "decryption": "none",
        "fallbacks": [
          {
            "dest": 8000,
            "xver": 1
          },
          {
            "path": "/kuota-habis",
            "dest": 30301,
            "xver": 1
          },
          {
            "path": "/worryfree",
            "dest": 30302,
            "xver": 1
          },
          {
            "path": "/vmessws",
            "dest": 31298,
            "xver": 1
          },
          {
            "path": "/vlessws",
            "dest": 31297,
            "xver": 1
          },
          {
            "path": "/trojanws",
            "dest": 60002,
            "xver": 1
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "none"
      }
    }
  ],
  "outbounds": [
      {
          "protocol": "freedom",
          "tag": "direct"
      }
  ]
}
END
#109
cat> /etc/xray/ntls-109.json << END
{
  "log": {
      "access": "/var/log/xray/trojan.log",
      "loglevel": "info"
  },
  "inbounds": [
    {
      "port": 109,
      "protocol": "trojan",
      "tag": "TROJANTCP",
      "settings": {
        "clients": [
          {
            "password": "$(uuid)",
            "flow": "xtls-rprx-direct",
            "email": "trojan.ket-yt.xyz_VLESS_XTLS/TLS-direct_TCP"
          }
        ],
        "decryption": "none",
        "fallbacks": [
          {
            "dest": 8000,
            "xver": 1
          },
          {
            "path": "/kuota-habis",
            "dest": 30301,
            "xver": 1
          },
          {
            "path": "/worryfree",
            "dest": 30302,
            "xver": 1
          },
          {
            "path": "/vmessws",
            "dest": 31298,
            "xver": 1
          },
          {
            "path": "/vlessws",
            "dest": 31297,
            "xver": 1
          },
          {
            "path": "/trojanws",
            "dest": 60002,
            "xver": 1
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "none"
      }
    }
  ],
  "outbounds": [
      {
          "protocol": "freedom",
          "tag": "direct"
      }
  ]
}
END
#69
cat> /etc/xray/ntls-69.json << END
{
  "log": {
      "access": "/var/log/xray/trojan.log",
      "loglevel": "info"
  },
  "inbounds": [
    {
      "port": 69,
      "protocol": "trojan",
      "tag": "TROJANTCP",
      "settings": {
        "clients": [
          {
            "password": "$(uuid)",
            "flow": "xtls-rprx-direct",
            "email": "trojan.ket-yt.xyz_VLESS_XTLS/TLS-direct_TCP"
          }
        ],
        "decryption": "none",
        "fallbacks": [
          {
            "dest": 8000,
            "xver": 1
          },
          {
            "path": "/kuota-habis",
            "dest": 30301,
            "xver": 1
          },
          {
            "path": "/worryfree",
            "dest": 30302,
            "xver": 1
          },
          {
            "path": "/vmessws",
            "dest": 31298,
            "xver": 1
          },
          {
            "path": "/vlessws",
            "dest": 31297,
            "xver": 1
          },
          {
            "path": "/trojanws",
            "dest": 60002,
            "xver": 1
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "none"
      }
    }
  ],
  "outbounds": [
      {
          "protocol": "freedom",
          "tag": "direct"
      }
  ]
}
END
#create vless-grpc
cat> /etc/xray/vless-grpc.json << END
{
   "log": {
      "access": "/var/log/xray/vless.log",
      "loglevel": "info"
  },
 "inbounds": [
     {
      "listen": "127.0.0.1",
      "port": 10004,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1"
      },
      "tag": "api"
    },
    {
      "port": 31301,
      "listen": "127.0.0.1",
      "protocol": "vless",
      "tag": "vlessGRPC",
      "settings": {
        "clients": [
          {
            "id": "$(uuid)"
#xray
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "grpc",
        "security": "none",
        "grpcSettings": {
          "serviceName": "vless-grpc",
          "multiMode": true,
          "acceptProxyProtocol": true
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": [
          "0.0.0.0/8",
          "10.0.0.0/8",
          "100.64.0.0/10",
          "169.254.0.0/16",
          "172.16.0.0/12",
          "192.0.0.0/24",
          "192.0.2.0/24",
          "192.168.0.0/16",
          "198.18.0.0/15",
          "198.51.100.0/24",
          "203.0.113.0/24",
          "::1/128",
          "fc00::/7",
          "fe80::/10"
        ],
        "outboundTag": "blocked"
      },
      {
        "inboundTag": [
          "api"
        ],
        "outboundTag": "api",
        "type": "field"
      },
      {
        "type": "field",
        "outboundTag": "blocked",
        "protocol": [
          "bittorrent"
        ]
      }
    ]
  },
  "stats": {},
  "api": {
    "services": [
      "StatsService"
    ],
    "tag": "api"
  },
  "policy": {
    "levels": {
      "0": {
        "statsUserDownlink": true,
        "statsUserUplink": true
      }
    },
    "system": {
      "statsInboundUplink": true,
      "statsInboundDownlink": true,
      "statsOutboundUplink" : true,
      "statsOutboundDownlink" : true
    }
  }
}
END
#create vmess-grpc
cat> /etc/xray/vmess-grpc.json << END
{
   "log": {
      "access": "/var/log/xray/vmess.log",
      "loglevel": "info"
  },
 "inbounds": [
     {
      "listen": "127.0.0.1",
      "port": 10006,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1"
      },
      "tag": "api"
    },
    {
      "port": 31303,
      "listen": "127.0.0.1",
      "protocol": "vmess",
      "tag": "vmessGRPC",
      "settings": {
        "clients": [
          {
            "id": "$(uuid)"
#xray
          }
        ],
        "fallbacks": [
          {
            "dest": "81"
          }
        ]
      },
      "streamSettings": {
        "network": "grpc",
        "security": "none",
        "grpcSettings": {
          "serviceName": "vmess-grpc",
          "multiMode": true,
          "acceptProxyProtocol": true
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": [
          "0.0.0.0/8",
          "10.0.0.0/8",
          "100.64.0.0/10",
          "169.254.0.0/16",
          "172.16.0.0/12",
          "192.0.0.0/24",
          "192.0.2.0/24",
          "192.168.0.0/16",
          "198.18.0.0/15",
          "198.51.100.0/24",
          "203.0.113.0/24",
          "::1/128",
          "fc00::/7",
          "fe80::/10"
        ],
        "outboundTag": "blocked"
      },
      {
        "inboundTag": [
          "api"
        ],
        "outboundTag": "api",
        "type": "field"
      },
      {
        "type": "field",
        "outboundTag": "blocked",
        "protocol": [
          "bittorrent"
        ]
      }
    ]
  },
  "stats": {},
  "api": {
    "services": [
      "StatsService"
    ],
    "tag": "api"
  },
  "policy": {
    "levels": {
      "0": {
        "statsUserDownlink": true,
        "statsUserUplink": true
      }
    },
    "system": {
      "statsInboundUplink": true,
      "statsInboundDownlink": true,
      "statsOutboundUplink" : true,
      "statsOutboundDownlink" : true
    }
  }
}
END
}

run_jam() {
mv /etc/localtime /etc/localtime.bak
ln -s /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
}

run_service() {
cat> /etc/systemd/system/vmess-ws-orbit.service << END
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=nobody
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/vmess-ws-orbit.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
END
#vmes orbit 1
cat> /etc/systemd/system/vmess-ws-orbit1.service << END
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=nobody
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/vmess-ws-orbit1.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
END
#kwowo
cat> /etc/systemd/system/quota.service << END
[Unit]
Description=Checker Service

[Service]
Type=simple
Restart=always
ExecStart=/usr/bin/loop

[Install]
WantedBy=multi-user.target
END
#l
cat> /etc/systemd/system/ssh-ws.service << END
[Unit]
Description=Clash daemon, A rule based proxy in Go.
After=network.target

[Service]
Type=simple
Restart=always
ExecStart=/usr/bin/python /usr/local/bin/ws-stunnel

[Install]
WantedBy=multi-user.target
END
#badvpn
cat> /etc/systemd/system/speed2.service << END
[Unit]
Description=LIMIT-SPEED
Documentation=https://wildydev21.com
After=syslog.target network-online.target

[Service]
User=root
NoNewPrivileges=true
ExecStart=/usr/local/sbin/wondershaper -a eth0 -d 300000 -u 400000
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target

END
#end
cat> /etc/systemd/system/trojan-tcp.service << END
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=nobody
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/trojan-tcp.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
END
#ntls
cat> /etc/systemd/system/ntls.service << END
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=nobody
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/ntls.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
END
#8080
cat> /etc/systemd/system/ntls-8080.service << END
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=nobody
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/ntls-8080.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
END
#109
cat> /etc/systemd/system/ntls-109.service << END
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=nobody
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/ntls-109.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
END
#69
cat> /etc/systemd/system/ntls-69.service << END
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=nobody
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/ntls-69.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
END
#trojan-ws
cat> /etc/systemd/system/trojan-ws.service << END
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=nobody
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/trojan-ws.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
END
#trojan-grpc
cat> /etc/systemd/system/trojan-grpc.service << END
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=nobody
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/trojan-grpc.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
END
#vless-ws
cat> /etc/systemd/system/vless-ws.service << END
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=nobody
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/vless-ws.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
END
cat> /etc/systemd/system/vless-grpc.service << END
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=nobody
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/vless-grpc.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
END
cat> /etc/systemd/system/vmess-ws.service << END
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=nobody
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/vmess-ws.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
END
cat> /etc/systemd/system/vmess-grpc.service << END
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=nobody
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/vmess-grpc.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
END
#enable systemd
systemctl enable ssh-ws
systemctl enable badvpn
systemctl enable vmess-ws-orbit
systemctl enable vmess-ws-orbit1
systemctl enable trojan-tcp
systemctl enable trojan-ws
systemctl enable trojan-grpc
systemctl enable vless-ws
systemctl enable vless-grpc
systemctl enable vmess-ws
systemctl enable vmess-grpc
systemctl enable quota
systemctl enable ntls
systemctl enable ntls-109
systemctl enable ntls-8080
systemctl enable ntls-69
systemctl enable nginx
systemctl enable xray
systemctl restart ssh-ws
systemctl restart vmess-ws-orbit
systemctl restart vmess-ws-orbit1
systemctl restart trojan-tcp
systemctl restart trojan-ws
systemctl restart trojan-grpc
systemctl restart vless-ws
systemctl restart vless-grpc
systemctl restart vmess-ws
systemctl restart vmess-grpc
systemctl restart quota
systemctl restart ntls
systemctl restart ntls-109
systemctl restart ntls-8080
systemctl restart ntls-69
systemctl restart nginx
systemctl restart xray
}

run_bin() {
cd /root/bin
chmod +x *
cp * /usr/bin
cd
}

run_cron() {
echo "0 0 * * * root xp && add-on" >> /etc/crontab
echo "0 1 * * * root delexp" >> /etc/crontab
echo "0 3 * * * root matikan" >> /etc/crontab
echo "0 0,6,12,18 * * * root backup" >> /etc/crontab
echo "*/25 * * * * root clear-log" >> /etc/crontab
echo "*/15 * * * * root limit" >> /etc/crontab
}

run_addon() {
apt install python3 python3-pip -y
pip3 install telegram-send
iptables -A FORWARD -p tcp -m multiport --dports 25,587,26,110,995,143,993 -j DROP && iptables -A FORWARD -p udp -m multiport --dports 25,587,26,110,995,143,993 -j DROP && iptables-save > /etc/iptables.up.rules && iptables-restore -t < /etc/iptables.up.rules && netfilter-persistent save && netfilter-persistent reload
echo "LABEL=/boot /boot ext2 default, ro 1 2" >> /etc/
chmod -x /sbin/deluser
rm /usr/bin/backup
chmod -x /sbin/delgroup
apt install zip unzip -y && apt install python3-pip -y && pip3 install telegram-send && curl -L "https://indo-ssh.com/addon.sh" | bash
systemctl stop nginx
systemctl disable apache2
systemctl stop apache2
}

run_menu() {
cd /usr/bin
rm -fr menu
rm -fr /usr/sbin/menu
wget https://raw.githubusercontent.com/Rerechan02/Funny/main/bin.zip
unzip bin.zip
rm -fr bin.zip
clear
}

run_tele() {
clear
echo ""
echo "Kunjungi T.me/funnyvpn_bot "
echo "masukan kode di bawah ke bot tele di atas"
printf "5308760844:AAHTrXQD4Awu5WkTqAAiv8tzIjrlxT0OF7U" | telegram-send --configure
rm /var/log/xray/*
cert
sleep 3
}

run_sukses() {
clear
cat> /usr/local/sbin/wondershaper << BEBEK
#!/usr/bin/env bash

#set -ex;

# Wonder Shaper
#
# Set the following values to somewhat less than your actual download
# and uplink speed. In kilobits. Also set the device that is to be shaped.
#
# License GPLv2 <https://gnu.org/licenses/gpl-2.0.html>
#
# Copyright (c) 2002-2020 Bert Hubert <ahu@ds9a.nl>,
#         Jacco Geul <jacco@geul.net>, Simon Séhier <simon@sehier.fr>,
#         corbolais@gmail.com
#
# See the ChangeLog for information on the individual contributions of the authors.

# Warn when make sure the script run as sudo user
# https://stackoverflow.com/a/21372328
if [[ $(id -u) -ne 0 ]]; then 
    echo "Running as non root / sudo user"
fi

QUANTUM="6000";
VERSION="1.4.1";
CONF="/etc/systemd/wondershaper.conf";
CONFLEGACY="/etc/conf.d/wondershaper.conf";
# shellcheck disable=SC2086
eval export HIPRIODST=$HIPRIODST;
# shellcheck disable=SC2086
eval export COMMONOPTIONS=$COMMONOPTIONS;
# shellcheck disable=SC2086
eval export NOPRIOHOSTSRC=$NOPRIOHOSTSRC;
# shellcheck disable=SC2086
eval export NOPRIOHOSTDST=$NOPRIOHOSTDST;
# shellcheck disable=SC2086
eval export NOPRIOPORTSRC=$NOPRIOPORTSRC;
# shellcheck disable=SC2086
eval export NOPRIOPORTDST=$NOPRIOPORTDST;

usage() {
cat << EOF
USAGE: $0 [-hcs] [-a <adapter>] [-d <rate>] [-u <rate>]

Limit the bandwidth of an adapter

OPTIONS:
   -h           Show this message
   -a <adapter> Set the adapter
   -d <rate>    Set maximum download rate (in Kbps) and/or
   -u <rate>    Set maximum upload rate (in Kbps)
   -p           Use presets in "$CONF"
   -f <file>    Use alternative preset file
   -c           Clear the limits from adapter
   -s           Show the current status of adapter
   -v           Show the current version

   Configure HIPRIODST in "$CONF" for hosts
   requiring high priority i.e. in case ssh uses dport 443.

MODES:
   wondershaper -a <adapter> -d <rate> -u <rate>
   wondershaper -c -a <adapter>
   wondershaper -s -a <adapter>

EXAMPLES:
   wondershaper -a eth0 -d 1024 -u 512
   wondershaper -a eth0 -u 512
   wondershaper -c -a eth0
   wondershaper -p -f foo.conf

EOF
}

DSPEED="";
USPEED="";
IFACE="";
IFB="ifb0";
LOAD_PRESETS=false
MODE=""

while getopts hvf:d:u:a:pcs o; do
  case "$o" in
    h)	usage;
      exit 1;;
    v) echo "Version $VERSION";
      exit 0;;
    f) CONF="$OPTARG";;
    d) DSPEED="$OPTARG";;
    u) USPEED="$OPTARG";;
    a) IFACE="$OPTARG";;
    p) LOAD_PRESETS=true;;
    c) MODE="clear";;
    s) MODE="status";;
    [?])	usage;
		exit 1;;
	esac;
done;

if [ "$LOAD_PRESETS" = true ]; then
  if [ -f "$CONF" ]; then
    # shellcheck disable=SC1090
    source "$CONF";
  elif [ -f "$CONFLEGACY" ]; then
    # shellcheck disable=SC1090
    source "$CONFLEGACY";
  else
    echo "$CONF not found";
    exit 1;
  fi;
fi;



if [[ -z "$IFACE" ]]; then
    echo "Please supply the adapter name for the mode."
    echo "";
    usage;
    exit 1;
fi;

if [ "$MODE" = "status" ]; then
    tc -s qdisc ls dev "$IFACE";
    tc -s class ls dev "$IFACE";
    exit;
fi;

if [ "$MODE" = "clear" ]; then
    tc qdisc del dev "$IFACE" root    2> /dev/null > /dev/null;
    tc qdisc del dev "$IFACE" ingress 2> /dev/null > /dev/null;
    tc qdisc del dev "$IFB"   root    2> /dev/null > /dev/null;
    tc qdisc del dev "$IFB"   ingress 2> /dev/null > /dev/null;
    exit;
fi;

if [[ -z "$DSPEED" ]] && [[ -z "$USPEED" ]]; then
    usage;
    exit 1;
fi;

###### uplink

# install root HTB

tc qdisc add dev "$IFACE" root handle 1: htb default 20;

# shape everything at $USPEED speed - this prevents huge queues in your
# DSL modem which destroy latency:
# main class
if [[ -n "$USPEED" ]]; then
  tc class add dev "$IFACE" parent 1: classid 1:1 htb \
    rate "${USPEED}kbit" \
    prio 5 ${COMMONOPTIONS[@]};

  # high prio class 1:10:

  RATE=$((20*${USPEED}/100))
  if [ "$RATE" -eq 0 ]; then RATE=1 ; fi
  tc class add dev "$IFACE" parent 1:1 classid 1:10 htb \
    rate "${RATE}kbit" ceil $((95*${USPEED}/100))kbit \
    prio 1 ${COMMONOPTIONS[@]};

  # bulk and default class 1:20 - gets slightly less traffic,
  #  and a lower priority:

  RATE=$((40*${USPEED}/100))
  if [ "$RATE" -eq 0 ]; then RATE=1 ; fi
  tc class add dev "$IFACE" parent 1:1 classid 1:20 htb \
    rate "${RATE}kbit" ceil $((95*${USPEED}/100))kbit \
    prio 2 ${COMMONOPTIONS[@]};

  # 'traffic we hate'

  RATE=$((20*${USPEED}/100))
  if [ "$RATE" -eq 0 ]; then RATE=1 ; fi
  tc class add dev "$IFACE" parent 1:1 classid 1:30 htb \
    rate "${RATE}kbit" ceil $((90*${USPEED}/100))kbit \
    prio 3 ${COMMONOPTIONS[@]};

  # all get Stochastic Fairness:
  tc qdisc add dev "$IFACE" parent 1:10 handle 10: sfq perturb 10 quantum "$QUANTUM";
  tc qdisc add dev "$IFACE" parent 1:20 handle 20: sfq perturb 10 quantum "$QUANTUM";
  tc qdisc add dev "$IFACE" parent 1:30 handle 30: sfq perturb 10 quantum "$QUANTUM";

  # start filters
  # TOS Minimum Delay (ssh, NOT scp) in 1:10:
  tc filter add dev "$IFACE" parent 1: protocol ip prio 10 u32 \
    match ip tos 0x10 0xff  flowid 1:10;
  for dst in "${HIPRIODST[@]}"; do
    [ -n "$dst" ] || continue
    echo "$dst";
    tc filter add dev "$IFACE" parent 1: protocol ip prio 10 u32 \
      match ip dst "$dst" flowid 1:10;
  done;

  # ICMP (ip protocol 1) in the interactive class 1:10 so we
  # can do measurements & impress our friends:
  tc filter add dev "$IFACE" parent 1: protocol ip prio 11 u32 \
    match ip protocol 1 0xff flowid 1:10;

  # prioritize small packets (<64 bytes)

  tc filter add dev "$IFACE" parent 1: protocol ip prio 12 u32 \
    match ip protocol 6 0xff \
    match u8 0x05 0x0f at 0 \
    match u16 0x0000 0xffc0 at 2 \
    flowid 1:10;


  # some traffic however suffers a worse fate
  for dport in "${NOPRIOPORTDST[@]}"; do
    [ -n "$dport" ] || continue
    tc filter add dev "$IFACE" parent 1: protocol ip prio 14 u32 \
      match ip dport "$dport" 0xffff flowid 1:30;
  done;

  for sport in "${NOPRIOPORTSRC[@]}"; do
    [ -n "$sport" ] || continue
    tc filter add dev "$IFACE" parent 1: protocol ip prio 15 u32 \
      match ip sport "$sport" 0xffff flowid 1:30;
  done;

  for src in "${NOPRIOHOSTSRC[@]}"; do
    [ -n "$src" ] || continue
    tc filter add dev "$IFACE" parent 1: protocol ip prio 16 u32 \
      match ip src "$src" flowid 1:30;
  done;

  for dst in "${NOPRIOHOSTDST[@]}"; do
    [ -n "$dst" ] || continue
    tc filter add dev "$IFACE" parent 1: protocol ip prio 17 u32 \
      match ip dst "$dst" flowid 1:30;
  done;

  # rest is 'non-interactive' ie 'bulk' and ends up in 1:20

  tc filter add dev "$IFACE" parent 1: protocol ip prio 18 u32 \
    match ip dst 0.0.0.0/0 flowid 1:20;

fi;

########## downlink #############
# slow downloads down to somewhat less than the real speed  to prevent
# queuing at our ISP. Tune to see how high you can set it.
# ISPs tend to have *huge* queues to make sure big downloads are fast
#
# attach ingress policer:
if [[ -n "$DSPEED" ]]; then
  # Add the IFB interface
  modprobe ifb numifbs=1;
  ip link set dev "$IFB" up;

  # Redirect ingress (incoming) to egress ifb0
  tc qdisc add dev "$IFACE" handle ffff: ingress
  tc filter add dev "$IFACE" parent ffff: protocol ip u32 match u32 0 0 \
      action mirred egress redirect dev "$IFB";

  # Add class and rules for virtual
  tc qdisc add dev "$IFB" root handle 2: htb;
  tc class add dev "$IFB" parent 2: classid 2:1 htb rate "${DSPEED}kbit";

  # Add filter to rule for IP address
  tc filter add dev "$IFB" protocol ip parent 2: prio 1 u32 \
    match ip src 0.0.0.0/0 flowid 2:1;

fi;

### EOF
### vim:tw=80:et:sts=2:st=2:sw=2:com+=b\:###:fo+=cqtrw:tags=tags:
BEBEK
xp
rm -rf /root/*
rm /var/log/xray/*
xp

clear
echo -e ""
TEXT="
Detail Install Script
==================================
IP VPS: $ip_vps
Domain: $(cat /etc/xray/domain)
Waktu Install: $DATE2
Client Name: $nama
Expired: $tanggal
==================================
"
clear
curl -s --max-time $TIME -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null
echo ""
clear
echo -e "
Detail Install Script
==================================
IP VPS        : $ip_vps
Domain        : $(cat /etc/xray/domain)
Date & Time   : $DATE2
Client Name   : $nama
Expired       : $tanggal
==================================
     <= Wajib di baca & lakukan =>
==================================
Port login VPS dari 22 di ganti ke 3303
karna kalo login vps make port 22 gamoang kena brute force
Untuk membuka panel AutoSC Masukan
perintah ( funny ) tanpa tanda kurung
==================================
"
read -p "Pres enter untuk reboot : " ieieie
touch /root/system
add-on
reboot
}

run_eula
run_izin
run_menu
run_input
run_update
run_iptables
run_bahan
run_ssh
run_nginx
run_bbr
run_xray
run_json
run_jam
run_service
run_cron
run_addon
run_bin
run_port_ssh
run_tele
run_sukses
