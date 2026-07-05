#!/usr/bin/env bash
set -o pipefail

# 等待1秒, 避免curl下载脚本的打印与脚本本身的显示冲突, 吃掉了提示用户按回车继续的信息
sleep 1

echo -e "                     _ ___                   \n ___ ___ __ __ ___ _| |  _|___ __ __   _ ___ \n|-_ |_  |  |  |-_ | _ |   |- _|  |  |_| |_  |\n|___|___|  _  |___|___|_|_|___|  _  |___|___|\n   [...]"
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

# 端口校验：输入为端口字符串，输出为校验状态，无副作用。
validate_port() {
    local input_port=$1
    [[ $input_port =~ ^[0-9]+$ ]] && [[ $input_port -ge 1 ]] && [[ $input_port -le 65535 ]]
}

# UUID 校验：输入为 UUID 字符串，输出为校验状态，无副作用。
validate_uuid() {
    local input_uuid=$1
    [[ $input_uuid =~ ^[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}$ ]]
}

# ShortID 校验：输入为十六进制 ShortID，输出为校验状态，无副作用。
validate_shortid() {
    local input_shortid=$1
    [[ ${#input_shortid} -le 16 ]] && [[ $(( ${#input_shortid} % 2 )) -eq 0 ]] && [[ $input_shortid =~ ^[0-9a-fA-F]*$ ]]
}

# Reality 密钥生成：依赖 sing-box 命令，输出 private_key 和 public_key 全局变量。
generate_reality_keypair() {
    local key_output
    key_output=$(sing-box generate reality-keypair)
    private_key=$(echo "${key_output}" | awk '/PrivateKey/ {print $2}')
    public_key=$(echo "${key_output}" | awk '/PublicKey/ {print $2}')

    if [[ -z "${private_key}" || -z "${public_key}" ]]; then
      echo -e "${red}sing-box Reality 密钥生成失败${none}"
      return 1
    fi
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

# 指定 sing-box 版本，留空表示使用官方安装脚本的最新稳定版本
SING_BOX_VERSION=""

# 执行脚本带参数
if [ $# -ge 1 ]; then
    # 第1个参数是 port
    port=${1}
    if [[ -z $port ]]; then
      port=443
    fi
    if ! validate_port "${port}"; then
        error
        exit 1
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
    if ! validate_uuid "${uuid}"; then
        error
        exit 1
    fi

    ip=${IPv4}
    echo -e "$yellow 本机IP = ${cyan}${ip}${none}"
    echo -e "$yellow 端口 (Port) = ${cyan}${port}${none}"
    echo -e "$yellow 用户ID (UUID) = $cyan${uuid}${none}"
    echo -e "$yellow SNI = ${cyan}$domain${none}"
    echo "----------------------------------------------------------------"
fi

# ============================================
# 安装函数
# ============================================
install_sing_box() {

if [[ -z $port ]]; then
  read -p "按回车键开始安装..."
fi

# 准备工作
apt update
apt install -y curl wget sudo net-tools lsof

# sing-box 官方脚本安装版本
echo
if [[ -n "${SING_BOX_VERSION}" ]]; then
  echo -e "${yellow}sing-box 官方脚本安装版本 ${SING_BOX_VERSION}$none"
else
  echo -e "${yellow}sing-box 官方脚本安装最新稳定版本$none"
fi
echo "----------------------------------------------------------------"
if [[ -n "${SING_BOX_VERSION}" ]]; then
  if ! curl -fsSL https://sing-box.app/install.sh | sh -s -- --version "${SING_BOX_VERSION}"; then
    echo -e "${red}sing-box 安装脚本执行失败${none}"
    return 1
  fi
else
  if ! curl -fsSL https://sing-box.app/install.sh | sh; then
    echo -e "${red}sing-box 安装脚本执行失败${none}"
    return 1
  fi
fi

if ! command -v sing-box >/dev/null 2>&1; then
  echo -e "${red}sing-box 安装失败，未找到 sing-box 命令${none}"
  return 1
fi

mkdir -p /etc/sing-box /var/log/sing-box

# 如果脚本带参数执行的, 要在安装了 sing-box 之后再生成私钥公钥 ShortID
if [[ -n $uuid ]]; then
  # 生成私钥公钥
  generate_reality_keypair || return 1

  # ShortID
  shortid=$(echo -n ${uuid} | sha1sum | head -c 16)
  
  echo
  echo "私钥公钥要在安装 sing-box 之后才可以生成"
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

# VLESS UUID
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
  # 生成私钥公钥
  generate_reality_keypair || return 1
  default_private_key=${private_key}
  default_public_key=${public_key}
  
  echo -e "请输入 "$yellow"x25519 Private Key"$none" x25519私钥 :"
  read -p "$(echo -e "(默认私钥 Private Key: ${cyan}${default_private_key}$none):")" private_key
  if [[ -z "$private_key" ]]; then 
    private_key=$default_private_key
    public_key=$default_public_key
  else
    echo -e "${yellow}sing-box 不能从手动输入的私钥反算公钥，请同时输入对应公钥。$none"
    read -p "$(echo -e "请输入 x25519 Public Key 公钥:")" public_key
    while [[ -z "$public_key" ]]; do
      error
      read -p "$(echo -e "请输入 x25519 Public Key 公钥:")" public_key
    done
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
    if ! validate_shortid "${shortid}"; then
      error
      continue
    else
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
  read -p "(默认: www.msn.com): " domain
  [ -z "$domain" ] && domain="www.msn.com"

  echo
  echo
  echo -e "$yellow SNI = ${cyan}$domain$none"
  echo "----------------------------------------------------------------"
  echo
fi




# 配置 config.json
echo
echo -e "$yellow 配置 /etc/sing-box/config.json $none"
echo "----------------------------------------------------------------"

# 生成配置
cat > /etc/sing-box/config.json <<-EOF
{
  "log": {
    "level": "warn",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-in",
      "listen": "0.0.0.0",
      "listen_port": ${port},
      "users": [
        {
          "uuid": "${uuid}",
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "${domain}",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "${domain}",
            "server_port": 443
          },
          "private_key": "${private_key}",
          "short_id": [
            "${shortid}"
          ]
        }
      }
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ]
}
EOF


echo
echo -e "$yellow校验 sing-box 配置$none"
echo "----------------------------------------------------------------"
if sing-box check -c /etc/sing-box/config.json; then
    echo -e "$green✓ sing-box 配置校验通过$none"
else
    echo -e "${red}sing-box 配置校验失败，已停止启动${none}"
    return 1
fi


# 重启 sing-box
echo
echo -e "$yellow重启 sing-box$none"
echo "----------------------------------------------------------------"

systemctl restart sing-box
sleep 1

if systemctl is-active --quiet sing-box; then
    echo -e "$green✓ sing-box 已成功启动$none"
else
    echo -e "${red}sing-box 启动失败${none}"
    echo -e "${yellow}sing-box 服务状态:${none}"
    systemctl status sing-box --no-pager -l
    echo -e "${yellow}sing-box 最近日志:${none}"
    journalctl -u sing-box --no-pager -n 80
    return 1
fi

# 指纹FingerPrint
fingerprint="random"

# SpiderX
spiderx=""

echo
echo "---------- sing-box 配置信息 -------------"
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
echo -e "$yellow sing-box 版本 (Version) = ${cyan}$(sing-box version | head -n 1)${none}"



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
    echo -e "$red========== 卸载 sing-box ==========$none"
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
    systemctl stop sing-box 2>/dev/null || true
    systemctl disable sing-box 2>/dev/null || true
    pkill -9 sing-box 2>/dev/null || true
    
    # 删除 sing-box 二进制和配置
    echo "删除 sing-box..."
    rm -f /usr/local/bin/sing-box
    rm -f /usr/bin/sing-box
    rm -rf /etc/sing-box
    rm -rf /var/log/sing-box
    rm -f /etc/systemd/system/sing-box.service
    rm -f /lib/systemd/system/sing-box.service
    rm -f /usr/lib/systemd/system/sing-box.service
    
    # 重载 systemd
    systemctl daemon-reload 2>/dev/null || true
    
    echo
    echo -e "$green========== 卸载完成 ==========$none"
    echo -e "$yellow所有 sing-box 相关文件已删除$none"
    echo
    echo "已删除的内容:"
    echo "  - sing-box 二进制: /usr/local/bin/sing-box 或 /usr/bin/sing-box"
    echo "  - 配置目录: /etc/sing-box"
    echo "  - 日志目录: /var/log/sing-box"
    echo "  - Systemd 服务: sing-box.service"
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
    echo -e "$cyan========== sing-box VLESS Reality 管理脚本 ==========$none"
    echo
    echo -e "$green 1.$none 安装 sing-box Reality"
    echo -e "$green 2.$none 卸载 sing-box Reality"
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
        install_sing_box
        exit $?
    fi
    
    # 无参数：显示菜单
    while true; do
        show_menu
        read -p "$(echo -e "请选择 [${cyan}0-2${none}]: ")" choice
        
        case $choice in
            1)
                install_sing_box
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
