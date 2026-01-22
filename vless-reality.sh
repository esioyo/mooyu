# 等待1秒, 避免curl下载脚本的打印与脚本本身的显示冲突, 吃掉了提示用户按回车继续的信息
sleep 1

echo -e "                     _ ___                   \n ___ ___ __ __ ___ _| |  _|___ __ __   _ ___ \n|-_ |_  |  |  |-_ | _ |   |- _|  |  |_| |_  |\n|___|___|  _  |___|___|_|_|___|  _  |___|___|\n        |_____|               |_____|        "
red='\e[91m'
green='\e[92m'
yellow='\e[93m'
magenta='\e[95m'
cyan='\e[96m'
none='\e[0m'

error() {
    echo -e "\n$red 输入错误! $none\n"
}

warn() {
    echo -e "\n$yellow $1 $none\n"
}


# 确保有 curl 和 wget
apt-get -y install curl wget -qq


# 本机 IPv4 地址
InFaces=($(ls /sys/class/net/ | grep -E '^(eth|ens|eno|esp|enp|venet|vif)'))

for i in "${InFaces[@]}"; do
    Public_IPv4=$(curl -4s --interface "$i" -m 2 https://www.cloudflare.com/cdn-cgi/trace | grep -oP "ip=\K.*$")
    if [[ -n "$Public_IPv4" ]]; then
        IPv4="$Public_IPv4"
        break
    fi
done

# 使用随机 UUID
default_uuid=$(cat /proc/sys/kernel/random/uuid)

# 执行脚本带参数
if [ $# -ge 1 ]; then
    # 第1个参数是 port
    port=${1}
    if [[ -z $port ]]; then
      port=443
    fi

    # 第2个参数是域名
    domain=${2}
    if [[ -z $domain ]]; then
      domain="tesla.com"
    fi

    # 第3个参数是 UUID
    uuid=${3}
    if [[ -z $uuid ]]; then
        uuid=${default_uuid}
    fi

    # 第4个参数是是否启用 sni-filter
    use_sni_filter=${4}
    if [[ -z $use_sni_filter ]]; then
        use_sni_filter="n"
    fi

    ip=${IPv4}
    echo -e "$yellow 本机IP = ${cyan}${ip}${none}"
    echo -e "$yellow 端口 (Port) = ${cyan}${port}${none}"
    echo -e "$yellow 用户ID (UUID) = $cyan${uuid}${none}"
    echo -e "$yellow SNI = ${cyan}$domain${none}"
    echo -e "$yellow sni-filter = ${cyan}${use_sni_filter}${none}"
    echo "----------------------------------------------------------------"
fi

# ============================================
# 安装函数
# ============================================
install_xray() {

pause

# 准备工作
apt update
apt install -y curl wget sudo net-tools lsof

# Xray官方脚本 安装最新版本
echo
echo -e "${yellow}Xray官方脚本安装 v25.10.15 版本$none"
# echo -e "${yellow}Xray官方脚本安装最新版本$none"
echo "----------------------------------------------------------------"
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --version v25.10.15
# bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

# 更新 geodata
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install-geodata

# 如果脚本带参数执行的, 要在安装了xray之后再生成默认私钥公钥shortID
if [[ -n $uuid ]]; then
  # 私钥种子
  # x25519对私钥有一定要求, 不是任意随机的都满足要求, 所以下面这个字符串只能当作种子看待
  reality_key_seed=$(echo -n ${uuid} | md5sum | head -c 32 | base64 -w 0 | tr '+/' '-_' | tr -d '=')

  # 生成私钥公钥
  # xray x25519 如果接收一个合法的私钥, 会生成对应的公钥. 如果接收一个非法的私钥, 会先"修正"为合法的私钥. 这个"修正"的过程, 会修改其中的一些字节
  # https://github.dev/XTLS/Xray-core/blob/6830089d3c42483512842369c908f9de75da2eaa/main/commands/all/curve25519.go#L36
  tmp_key=$(echo -n ${reality_key_seed} | xargs xray x25519 -i)
  private_key=$(echo ${tmp_key} | awk '{print $2}')
  public_key=$(echo ${tmp_key} | awk '{print $4}')

  # ShortID
  shortid=$(echo -n ${uuid} | sha1sum | head -c 16)
  
  echo
  echo "私钥公钥要在安装xray之后才可以生成"
  echo -e "$yellow 私钥 (PrivateKey) = ${cyan}${private_key}${none}"
  echo -e "$yellow 公钥 (PublicKey) = ${cyan}${public_key}${none}"
  echo -e "$yellow ShortId = ${cyan}${shortid}${none}"
  echo "----------------------------------------------------------------"
fi

# 打开BBR
echo
echo -e "$yellow打开BBR$none"
echo "----------------------------------------------------------------"
sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control = bbr" >>/etc/sysctl.conf
echo "net.core.default_qdisc = fq" >>/etc/sysctl.conf
sysctl -p >/dev/null 2>&1

# 配置 VLESS_Reality 模式, 需要:端口, UUID, x25519公私钥, 目标网站
echo
echo -e "$yellow配置 VLESS_Reality 模式$none"
echo "----------------------------------------------------------------"

# 使用 IPv4
ip=${IPv4}

# 端口
if [[ -z $port ]]; then
  default_port=443
  while :; do
    read -p "$(echo -e "请输入端口 [${magenta}1-65535${none}] Input port (默认Default ${cyan}${default_port}$none):")" port
    [ -z "$port" ] && port=$default_port
    case $port in
    [1-9] | [1-9][0-9] | [1-9][0-9][0-9] | [1-9][0-9][0-9][0-9] | [1-5][0-9][0-9][0-9][0-9] | 6[0-4][0-9][0-9][0-9] | 65[0-4][0-9][0-9] | 655[0-3][0-5])
      echo
      echo
      echo -e "$yellow 端口 (Port) = ${cyan}${port}${none}"
      echo "----------------------------------------------------------------"
      echo
      break
      ;;
    *)
      error
      ;;
    esac
  done
fi

# Xray UUID
if [[ -z $uuid ]]; then
  while :; do
    echo -e "请输入 "$yellow"UUID"$none" "
    read -p "$(echo -e "(默认ID: ${cyan}${default_uuid}$none):")" uuid
    [ -z "$uuid" ] && uuid=$default_uuid
    case $(echo -n $uuid | sed -E 's/[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}//g') in
    "")
        echo
        echo
        echo -e "$yellow UUID = $cyan$uuid$none"
        echo "----------------------------------------------------------------"
        echo
        break
        ;;
    *)
        error
        ;;
    esac
  done
fi

# x25519公私钥
if [[ -z $private_key ]]; then
  # 私钥种子
  # x25519对私钥有一定要求, 不是任意随机的都满足要求, 所以下面这个字符串只能当作种子看待
  reality_key_seed=$(echo -n ${uuid} | md5sum | head -c 32 | base64 -w 0 | tr '+/' '-_' | tr -d '=')

  # 生成私钥公钥
  # xray x25519 如果接收一个合法的私钥, 会生成对应的公钥. 如果接收一个非法的私钥, 会先"修正"为合法的私钥. 这个"修正"的过程, 会修改其中的一些字节
  # https://github.dev/XTLS/Xray-core/blob/6830089d3c42483512842369c908f9de75da2eaa/main/commands/all/curve25519.go#L36
  tmp_key=$(echo -n ${reality_key_seed} | xargs xray x25519 -i)
  default_private_key=$(echo ${tmp_key} | awk '{print $2}')
  default_public_key=$(echo ${tmp_key} | awk '{print $4}')
  
  echo -e "请输入 "$yellow"x25519 Private Key"$none" x25519私钥 :"
  read -p "$(echo -e "(默认私钥 Private Key: ${cyan}${default_private_key}$none):")" private_key
  if [[ -z "$private_key" ]]; then 
    private_key=$default_private_key
    public_key=$default_public_key
  else
    tmp_key=$(echo -n ${private_key} | xargs xray x25519 -i)
    private_key=$(echo ${tmp_key} | awk '{print $2}')
    public_key=$(echo ${tmp_key} | awk '{print $4}')
  fi

  echo
  echo 
  echo -e "$yellow 私钥 (PrivateKey) = ${cyan}${private_key}$none"
  echo -e "$yellow 公钥 (PublicKey) = ${cyan}${public_key}$none"
  echo "----------------------------------------------------------------"
  echo
fi

# ShortID
if [[ -z $shortid ]]; then
  default_shortid=$(echo -n ${uuid} | sha1sum | head -c 16)
  while :; do
    echo -e "请输入 "$yellow"ShortID"$none" :"
    read -p "$(echo -e "(默认ShortID: ${cyan}${default_shortid}$none):")" shortid
    [ -z "$shortid" ] && shortid=$default_shortid
    if [[ ${#shortid} -gt 16 ]]; then
      error
      continue
    elif [[ $(( ${#shortid} % 2 )) -ne 0 ]]; then
      # 字符串包含奇数个字符
      error
      continue
    else
      # 字符串包含偶数个字符
      echo
      echo
      echo -e "$yellow ShortID = ${cyan}${shortid}$none"
      echo "----------------------------------------------------------------"
      echo
      break
    fi
  done
fi

# 目标网站
if [[ -z $domain ]]; then
  echo -e "请输入一个 ${magenta}伪装域名${none}"
  read -p "(默认: www.icloud.com): " domain
  [ -z "$domain" ] && domain="www.icloud.com"

  echo
  echo
  echo -e "$yellow SNI = ${cyan}$domain$none"
  echo "----------------------------------------------------------------"
  echo
fi





# 配置config.json
echo
echo -e "$yellow 配置 /usr/local/etc/xray/config.json $none"
echo "----------------------------------------------------------------"

# 生成配置
cat > /usr/local/etc/xray/config.json <<-EOF
{ // VLESS + Reality
  "log": {
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log",
    "loglevel": "warning"
  },
  "inbounds": [
    // [inbound] 如果你想使用其它翻墙服务端如(HY2或者NaiveProxy)对接v2ray的分流规则, 那么取消下面一段的注释, 并让其它翻墙服务端接到下面这个socks 1080端口
    // {
    //   "listen":"127.0.0.1",
    //   "port":1080,
    //   "protocol":"socks",
    //   "sniffing":{
    //     "enabled":true,
    //     "destOverride":[
    //       "http",
    //       "tls"
    //     ]
    //   },
    //   "settings":{
    //     "auth":"noauth",
    //     "udp":false
    //   }
    // },
    {
      "listen": "0.0.0.0",
      "port": ${port},    // ***
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${uuid}",    // ***
            "flow": "xtls-rprx-vision"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "${domain}:443",    // ***
          "xver": 0,
          "serverNames": ["${domain}"],    // ***
          "privateKey": "${private_key}",    // ***私钥
          "shortIds": ["${shortid}"]    // ***
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls", "quic"]
      }
    }
  ],
  "outbounds": [{
    "protocol": "freedom",
    "tag": "direct"
  }],
  "dns": {
    "servers": ["8.8.8.8", "1.1.1.1", "localhost"]
  },
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [{
      "type": "field",
      "ip": ["geoip:private"],
      "outboundTag": "block"
    }]
  }
}
EOF


# 重启 Xray 或启动 sni-filter 模式
echo
echo -e "$yellow重启 Xray$none"
echo "----------------------------------------------------------------"

service xray restart
sleep 1

if systemctl is-active --quiet xray; then
    echo -e "$green✓ Xray 已成功启动$none"
else
    echo -e "${red}Xray 启动失败${none}"
fi

# 指纹FingerPrint
fingerprint="random"

# SpiderX
spiderx=""

echo
echo "---------- Xray 配置信息 -------------"
echo -e "$green ---VLESS Reality 服务器配置--- $none"
echo -e "$yellow 地址 (Address) = $cyan${ip}$none"
echo -e "$yellow 端口 (Port) = ${cyan}${port}${none}"
echo -e "$yellow 用户ID (UUID) = $cyan${uuid}$none"
echo -e "$yellow 流控 (Flow) = ${cyan}xtls-rprx-vision${none}"
echo -e "$yellow 传输协议 (Network) = ${cyan}tcp$none"
echo -e "$yellow 底层传输安全 (TLS) = ${cyan}reality$none"
echo -e "$yellow SNI = ${cyan}${domain}$none"
echo -e "$yellow 指纹 (Fingerprint) = ${cyan}${fingerprint}$none"
echo -e "$yellow 公钥 (PublicKey) = ${cyan}${public_key}${none}"
echo -e "$yellow ShortId = ${cyan}${shortid}${none}"



echo
echo "---------- VLESS Reality URL ----------"
vless_reality_url="vless://${uuid}@${ip}:${port}?flow=xtls-rprx-vision&encryption=none&type=tcp&security=reality&sni=${domain}&fp=${fingerprint}&pbk=${public_key}&sid=${shortid}&spx=${spiderx}&#${ip}"
echo -e "${cyan}${vless_reality_url}${none}"
echo
echo "---------- END -------------"

echo
echo "安装完成！"
read -p "按回车键返回主菜单..." 
}

# ============================================
# 卸载函数
# ============================================
uninstall() {
    echo
    echo -e "$red========== 卸载 Xray 和 sni-filter ==========$none"
    echo
    read -p "$(echo -e "确认卸载吗？这将删除所有相关文件 [y/${cyan}N${none}]: ")" confirm
    
    if [[ ! "$confirm" =~ ^[yY]$ ]]; then
        echo -e "$yellow已取消卸载$none"
        return
    fi
    
    echo
    echo -e "$yellow正在卸载...$none"
    echo "----------------------------------------------------------------"
    
    # 停止所有进程
    echo "停止服务..."
    systemctl stop xray 2>/dev/null || true
    systemctl disable xray 2>/dev/null || true
    pkill -9 xray 2>/dev/null || true
    pkill -9 sni-filter 2>/dev/null || true
    
    # 删除 Xray 二进制和配置
    echo "删除 Xray..."
    rm -f /usr/local/bin/xray
    rm -rf /usr/local/etc/xray
    rm -rf /var/log/xray
    rm -f /etc/systemd/system/xray.service
    rm -f /etc/systemd/system/xray@.service
    
    # 删除 geodata 文件
    rm -f /usr/local/share/xray/*.dat
    

    
    # 重载 systemd
    systemctl daemon-reload 2>/dev/null || true
    
    echo
    echo -e "$green========== 卸载完成 ==========$none"
    echo -e "$yellow所有 Xray 和 sni-filter 相关文件已删除$none"
    echo
    echo "已删除的内容:"
    echo "  - Xray 二进制: /usr/local/bin/xray"
    echo "  - 配置目录: /usr/local/etc/xray"
    echo "  - 日志目录: /var/log/xray"
    echo "  - Systemd 服务: /etc/systemd/system/xray.service"
    echo "  - Geodata 数据: /usr/local/share/xray/*.dat"
    echo "  - sni-filter: ${workdir}/sni-filter"
    echo "  - 启动脚本: ${workdir}/start.sh"
    echo
    read -p "按回车键返回主菜单..."
}

# 显示主菜单
show_menu() {
    clear
    echo -e "                     _ ___                   "
    echo -e " ___ ___ __ __ ___ _| |  _|___ __ __   _ ___ "
    echo -e "|-_ |_  |  |  |-_ | _ |   |- _|  |  |_| |_  |"
    echo -e "|___|___|  _  |___|___|_|_|___|  _  |___|___|"
    echo -e "        |_____|               |_____|        "
    echo
    echo -e "$cyan========== Xray VLESS Reality 管理脚本 ==========$none"
    echo
    echo -e "$green 1.$none 安装 Xray Reality"
    echo -e "$green 2.$none 卸载 Xray Reality"
    echo -e "$green 0.$none 退出"
    echo
    echo "================================================"
    echo
}

# ============================================
# 主程序逻辑
# ============================================
main() {
    # 命令行参数处理
    if [[ "${1}" == "uninstall" ]]; then
        uninstall
        exit 0
    elif [[ $# -ge 1 ]]; then
        # 如果有参数，直接执行安装（保持向后兼容）
        install_xray
        exit 0
    fi
    
    # 无参数：显示菜单
    while true; do
        show_menu
        read -p "$(echo -e "请选择 [${cyan}0-2${none}]: ")" choice
        
        case $choice in
            1)
                install_xray
                ;;
            2)
                uninstall
                ;;
            0)
                echo -e "$yellow再见！$none"
                exit 0
                ;;
            *)
                echo -e "$red无效选项！$none"
                sleep 2
                ;;
        esac
    done
}

# 调用主菜单
main "$@"
