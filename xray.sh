clear
function permit_masuk() {
	dateFromServer=$(curl -v --insecure --silent https://google.com/ 2>&1 | grep Date | sed -e 's/< Date: //')
	biji=`date +"%Y-%m-%d" -d "$dateFromServer"`
	BURIQ () {
		curl -sS https://raw.githubusercontent.com/stunnel478/vpn-script/main/ip.txt > /root/tmp
		data=( `cat /root/tmp | grep -E "^### " | awk '{print $2}'` )
		for user in "${data[@]}"
		exp=( `grep -E "^### $user" "/root/tmp" | awk '{print $3}'` )
		d1=(`date -d "$exp" +%s`)
		d2=(`date -d "$biji" +%s`)
		exp2=$(( (d1 - d2) / 86400 ))
		if [[ "$exp2" -le "0" ]]; then
		echo $user > /etc/.$user.ini
		else
		rm -f /etc/.$user.ini > /dev/null 2>&1
		done
		rm -f /root/tmp
	}
	MYIP=$(curl -sS ipv4.icanhazip.com)
	Name=$(curl -sS https://raw.githubusercontent.com/stunnel478/vpn-script/main/ip.txt | grep $MYIP | awk '{print $2}')
	echo $Name > /usr/local/etc/.$Name.ini
	CekOne=$(cat /usr/local/etc/.$Name.ini)
	Bloman () {
	if [ -f "/etc/.$Name.ini" ]; then
		CekTwo=$(cat /etc/.$Name.ini)
		if [ "$CekOne" = "$CekTwo" ]; then
		res="Expired"
		else
		res="Permission Accepted..."
	}
	PERMISSION () {
		MYIP=$(curl -sS ipv4.icanhazip.com)
		IZIN=$(curl -sS https://raw.githubusercontent.com/stunnel478/vpn-script/main/ip.txt | awk '{print $4}' | grep $MYIP)
		if [ "$MYIP" = "$IZIN" ]; then
		Bloman
		else
		res="Permission Denied!"
	}
	BURIQ
	green() { echo -e "\\033[32;1m${*}\\033[0m"; }
	red() { echo -e "\\033[31;1m${*}\\033[0m"; }
	PERMISSION
	if [ -f /home/needupdate ]; then
	red "Your script need to update first !"
	exit 0
	elif [ "$res" = "Permission Accepted..." ]; then
	echo -ne
	else
	red "Permission Denied!"
	exit 0
}
function import_string() {
	export SCRIPT_URL='https://raw.githubusercontent.com/kurosewu/scc/main'
	export RED="\033[0;31m"
	export GREEN="\033[0;32m"
	export YELLOW="\033[0;33m"
	export BLUE="\033[0;34m"
	export PURPLE="\033[0;35m"
	export CYAN="\033[0;36m"
	export LIGHT="\033[0;37m"
	export NC="\033[0m"
	export ERROR="[${RED} ERROR ${NC}]"
	export INFO="[${YELLOW} INFO ${NC}]"
	export FAIL="[${RED} FAIL ${NC}]"
	export OKEY="[${GREEN} OKEY ${NC}]"
	export PENDING="[${YELLOW} PENDING ${NC}]"
	export SEND="[${YELLOW} SEND ${NC}]"
	export RECEIVE="[${YELLOW} RECEIVE ${NC}]"
	export RED_BG="\e[41m"
	export BOLD="\e[1m"
	export WARNING="${RED}\e[5m"
	export UNDERLINE="\e[4m"
}
function check_os() {
	if command -V apt > /dev/null 2>&1; then
		FCK='apt'
	elif command -V yum > /dev/null 2>&1; then
		FCK='yum'
	else
		clear
		echo -e "${FAIL} Sistem Operasi anda tidak didukung !"
		exit 1
	fi
}
function check_root() {
	if [[ $(whoami) != 'root' ]]; then
		clear
		echo -e "${FAIL} Gunakan User root dan coba lagi !"
		exit 1
	else
		export ROOT_CHK='true'
}
function check_architecture(){
	if [[ $(uname -m) == 'x86_64' ]]; then
		export ARCH_CHK='true'
	else
		clear
		echo -e "${FAIL} Architecture anda tidak didukung !"
		exit 1
	fi
}
function install_requirement() {
	clear
	read -p "Input ur domain : " hostname
	if [[ $hostname == "" ]]; then
	clear
	echo -e "${FAIL} first enter the domain before continuing !"
	exit 1
	mkdir -p /etc/xray/
	mkdir -p /etc/xray/core/
	mkdir -p /etc/xray/log/
	mkdir -p /etc/xray/config/
	echo "$hostname" >/etc/xray/domain.conf
	$FCK update -y
	$FCK upgrade -y
	$FCK dist-upgrade -y
	$FCK install shc -y
	$FCK install jq -y
	$FCK install sudo -y
	$FCK install -y bzip2 gzip coreutils screen curl unzip
	sysctl -w net.ipv6.conf.all.disable_ipv6=1
	sysctl -w net.ipv6.conf.default.disable_ipv6=1
	$FCK install figlet -y
	$FCK install ruby -y
	gem install lolcat
	rm /root/.bashrc
	wget -q -O .bashrc ${SCRIPT_URL}/.bashrc
	$FCK remove --purge nginx apache2 sendmail ufw firewalld exim4 -y >/dev/null 2>&1
	$FCK autoremove -y
	$FCK clean -y
	$FCK install build-essential apt-transport-https -y
	$FCK install zip unzip nano net-tools make git lsof wget curl jq bc gcc make cmake neofetch htop libssl-dev socat sed zlib1g-dev libsqlite3-dev libpcre3 libpcre3-dev libgd-dev -y
	$FCK-get install uuid-runtime
	lsof -t -i tcp:80 -s tcp:listen | xargs kill >/dev/null 2>&1
	lsof -t -i tcp:443 -s tcp:listen | xargs kill >/dev/null 2>&1
	rm -rf /root/.acme.sh
	systemctl stop nginx
	mkdir /root/.acme.sh
	curl https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
	chmod +x /root/.acme.sh/acme.sh
	/root/.acme.sh/acme.sh --upgrade --auto-upgrade
	/root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
	/root/.acme.sh/acme.sh --issue -d $hostname --standalone -k ec-256
	~/.acme.sh/acme.sh --installcert -d $hostname --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
	ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
	$FCK install libpcre3 libpcre3-dev zlib1g-dev dbus -y
	echo "deb http://nginx.org/packages/mainline/debian $(lsb_release -cs) nginx" |
	sudo tee /etc/apt/sources.list.d/nginx.list
	curl -fsSL https://nginx.org/keys/nginx_signing.key | apt-key add -
	$FCK update
	$FCK install nginx -y
	wget -q -O /etc/nginx/nginx.conf "${SCRIPT_URL}/nginx.conf"
	wget -q -O /etc/nginx/conf.d/xray.conf "${SCRIPT_URL}/xray.conf"
	rm -rf /etc/nginx/conf.d/default.conf
	systemctl enable nginx
	mkdir -p /home/vps/public_html
	chown -R www-data:www-data /home/vps/public_html
	chmod -R g+rw /home/vps/public_html
	echo "
	<head><meta name="robots" content="noindex" /></head>
	<title>Premium VPN Multi Port Xray</title>
	<body><pre><center><br><font color="BLACK" size="50"><b>Premium VPN Multi Port Xray</b><br></font>
	<img src="https://cdn.jsdelivr.net/npm/simple-icons@3.0.1/icons/github.svg" data-original-height="100" data-original-width="100" height="300" width="300"><br>
	<br><font color="BLACK" size="50"><b>Setup By M Fauzan Romandhoni</b></font>
	<br><br><font color="BLACK" size="50"><b>Facebook : fb.me/zan404</b></font>
	<br><font color="BLACK" size="50"><b>Telegram : t.me/zann404</b></font>
	</center></pre></body>
	" >/home/vps/public_html/index.html
	systemctl start nginx
	NET=$(ip -o $ANU -4 route show to default | awk '{print $5}')
	$FCK -y install vnstat
	/etc/init.d/vnstat restart
	$FCK -y install libsqlite3-dev
	wget -q https://humdi.net/vnstat/vnstat-2.9.tar.gz
	tar zxvf vnstat-2.9.tar.gz
	cd vnstat-2.9
	./configure --prefix=/usr --sysconfdir=/etc && make && make install
	vnstat -u -i $NET
	sed -i 's/Interface "'""eth0""'"/Interface "'""$NET""'"/g' /etc/vnstat.conf
	chown vnstat:vnstat /var/lib/vnstat -R
	systemctl enable vnstat
	/etc/init.d/vnstat restart
	rm -f /root/vnstat-2.9.tar.gz
	rm -rf /root/vnstat-2.9
	curl https://rclone.org/install.sh | bash >/dev/null 2>&1
	printf "q\n" | rclone config
	wget -q -O /root/.config/rclone/rclone.conf "${SCRIPT_URL}/rclone.conf"
	$FCK install msmtp-mta ca-certificates bsd-mailx -y

	cat <<EOF> /etc/msmtprc
	defaults
	tls on
	tls_starttls on
	tls_trust_file /etc/ssl/certs/ca-certificates.crt
	account default
	host smtp.gmail.com
	port 587
	auth on
	user virtinitti@gmail.com
	from virtinitti@gmail.com
	password Qazxcvbnm1
	EOF

	logfile ~/.msmtp.log
	chown -R www-data:www-data /etc/msmtprc
	wget -q -O /etc/xray/core/xray.zip "${SCRIPT_URL}/xray.zip"
	cd /etc/xray/core/
	unzip -o xray.zip
	rm -f xray.zip
	cd /root/
	mkdir -p /etc/xray/log/xray/
	mkdir -p /etc/xray/config/xray/
	wget -qO- "${SCRIPT_URL}/tls.json" | jq '.inbounds[0].streamSettings.xtlsSettings.certificates += [{"certificateFile": "'/root/.acme.sh/${hostname}_ecc/fullchain.cer'","keyFile": "'/root/.acme.sh/${hostname}_ecc/${hostname}.key'"}]' >/etc/xray/config/xray/tls.json
	wget -qO- "${SCRIPT_URL}/ntls.json" >/etc/xray/config/xray/nontls.json

	cat <<EOF> /etc/systemd/system/xray@.service
	[Unit]
	Description=XRay XTLS Service ( %i )
	Documentation=https://github.com/XTLS/Xray-core
	After=syslog.target network-online.target
	[Service]
	User=root
	NoNewPrivileges=true
	ExecStart=/etc/xray/core/xray -c /etc/xray/config/xray/%i.json
	LimitNPROC=10000
	LimitNOFILE=1000000
	Restart=on-failure
	RestartPreventExitStatus=23
	[Install]
	WantedBy=multi-user.target
	EOF

	systemctl daemon-reload
	systemctl stop xray@tls
	systemctl disable xray@tls
	systemctl enable xray@tls
	systemctl start xray@tls
	systemctl restart xray@tls
	systemctl stop xray@nontls
	systemctl disable xray@nontls
	systemctl enable xray@nontls
	systemctl start xray@nontls
	systemctl restart xray@nontls

	$FCK install python2 -y >/dev/null 2>&1
	cd /usr/bin
	wget -q -O menu "${SCRIPT_URL}/menu.sh"
	chmod +x menu
	wget -q -O speedtest "${SCRIPT_URL}/speedtest_cli.py"
	chmod +x speedtest
	cd /usr/bin
	wget -q -O xp "${SCRIPT_URL}/xp.sh"
	chmod +x /usr/bin/xp
	sed -i -e 's/\r$//' xp
	echo "0 3 * * * root reboot" >> /etc/crontab
	echo "0 0 * * * root xp" >> /etc/crontab
	mkdir /home/trojan
	mkdir /home/vmess
	mkdir /home/vless
	mkdir /home/shadowsocks
	cat >/home/vps/public_html/trojan.json <<END
	"TCP TLS" : "443",
	"WS TLS" : "443"
	cat >/home/vps/public_html/vmess.json <<END
	"WS TLS" : "443",
	"WS Non TLS" : "80"
	cat >/home/vps/public_html/vless.json <<END
	"WS TLS" : "443",
	"WS Non TLS" : "80"
	cat >/home/vps/public_html/ss.json <<END
	"WS TLS" : "443",
	"GRPC" : "443"
	touch /etc/xray/trojan-client.conf
	touch /etc/xray/vmess-client.conf
	touch /etc/xray/vless-client.conf
	touch /etc/xray/ss-client.conf
	mkdir -p /etc/xray/xray-cache/
	echo 'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin:/etc/xray/core:' >/etc/environment
	source /etc/environment
	clear
	sleep 3
	rm -rf /root/setup.sh
	echo ""
	/etc/init.d/nginx restart
	/etc/init.d/cron restart
	/etc/init.d/vnstat restart
	systemctl restart xray@tls
	systemctl restart xray@nontls
	echo -e "[ ${GREEN}ok${NC} ] Restarting Xray (via systemctl): xray.service."
	sleep 5
	echo "Restarting The Service Was Successful"
	sleep 3
	clear
	echo "Successful Installation"
	sleep 3
	clear
	echo "Reboot Process In 10 Seconds"
	sleep 10
	reboot
}
function main() {
permit_masuk
import_string
check_os
check_root
check_architecture
install_requirement
}
main
