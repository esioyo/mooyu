#!/bin/bash

# 检查并安装脚本运行所需依赖。
install_required_packages() {
    REQUIRED_PACKAGES=("curl" "openssl" "wget" "iptables")
    for pkg in "${REQUIRED_PACKAGES[@]}"; do
        if ! command -v $pkg &> /dev/null; then
            apt-get update > /dev/null 2>&1
            apt-get install -y $pkg > /dev/null 2>&1
        fi
    done
}

# 校验单个端口是否在 1-65535 范围内。
is_valid_port() {
    port_value="$1"
    [[ "$port_value" =~ ^[0-9]+$ ]] && [ "$port_value" -ge 1 ] && [ "$port_value" -le 65535 ]
}

# 校验 Hysteria 端口跳跃范围。
is_valid_port_range() {
    port_range_value="$1"

    if [[ "$port_range_value" =~ ^([0-9]+)-([0-9]+)$ ]]; then
        start_port="${BASH_REMATCH[1]}"
        end_port="${BASH_REMATCH[2]}"
        is_valid_port "$start_port" && is_valid_port "$end_port" && [ "$start_port" -lt "$end_port" ]
        return
    fi

    return 1
}

# 从现有 systemd 服务中读取已安装的 Hysteria2 二进制文件名。
get_installed_binary_name() {
    grep -oP 'ExecStart=/root/hysteria/\K[^ ]+' /etc/systemd/system/hysteria.service 2>/dev/null | head -1
}

# 从现有配置中读取监听值。
get_installed_listen_value() {
    grep -oP '^listen:\s*:\K[0-9]+(-[0-9]+)?' /root/hysteria/config.yaml 2>/dev/null | head -1
}

# 从现有配置中读取单端口监听值。
get_installed_listen_port() {
    listen_value=$(get_installed_listen_value)
    if [[ "$listen_value" =~ ^[0-9]+$ ]]; then
        echo "$listen_value"
    fi
}

# 从现有配置中读取端口跳跃范围。
get_installed_hop_range() {
    listen_value=$(get_installed_listen_value)
    if [[ "$listen_value" =~ ^[0-9]+-[0-9]+$ ]]; then
        echo "$listen_value"
        return
    fi

    # 兼容旧版脚本写入 systemd 手动转发规则的已安装实例。
    grep -oP -- '--dport \K[0-9]+:[0-9]+' /etc/systemd/system/hysteria.service 2>/dev/null | head -1 | tr ':' '-'
}

# 读取端口范围中的第一个端口。
get_first_port() {
    echo "$1" | cut -d '-' -f 1
}

# 生成 v2rayN 支持的 Hysteria2 端口 URI。
build_hysteria_uri() {
    uri_password="$1"
    uri_host="$2"
    uri_listen_port="$3"
    uri_hop_range="$4"

    uri_query="insecure=1&allowInsecure=1&sni=bing.com"
    if [ -n "$uri_hop_range" ]; then
        uri_query="${uri_query}&mport=${uri_hop_range}"
    fi

    echo "hysteria2://$uri_password@$uri_host:$uri_listen_port/?$uri_query"
}

# 写入 systemd 服务。
write_systemd_service() {
    service_binary="$1"

    cat > /etc/systemd/system/hysteria.service <<EOL
[Unit]
Description=Hysteria VPN Service
After=network.target nss-lookup.target

[Service]
User=root
WorkingDirectory=/root/hysteria
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
ExecStart=/root/hysteria/$service_binary server -c /root/hysteria/config.yaml
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=5
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOL
}

# 输出 v2rayN 可导入链接。
print_client_links() {
    link_password="$1"
    link_host="$2"
    link_listen_port="$3"
    link_hop_range="$4"
    client_uri=$(build_hysteria_uri "$link_password" "$link_host" "$link_listen_port" "$link_hop_range")

    echo "v2rayN 分享链接："
    echo "$client_uri"
    echo ""
}

# 检查是否已经安装 Hysteria。
if [ -d "/root/hysteria" ]; then
    echo "检测到 Hysteria 已经安装。"
    echo ""
    echo "请选择操作："
    echo ""
    echo "1) 重新安装"
    echo ""
    echo "2) 修改配置"
    echo ""
    echo "3) 卸载"
    echo ""
    read -p "请输入选项：" choice
    case $choice in
        1)
            # 重新安装前清理旧文件和服务。
            systemctl stop hysteria
            systemctl daemon-reload
            rm -rf /root/hysteria
            pkill -f 'hysteria*'
            systemctl disable hysteria > /dev/null 2>&1
            rm /etc/systemd/system/hysteria.service
            ;;
        2)
            # 修改现有配置并重启服务。
            cd /root/hysteria
        
            # 读取当前监听值、端口跳跃范围以及认证密码。
            current_listen_value=$(get_installed_listen_value)
            current_port=$(get_installed_listen_port)
            current_hop_range=$(get_installed_hop_range)
            if [ -z "$current_port" ] && [ -n "$current_hop_range" ]; then
                current_port=$(get_first_port "$current_hop_range")
            fi
            current_password=$(grep -m 1 'password:' config.yaml | awk -F': ' '{print $2}' | tr -d '[:space:]')
            installed_binary=$(get_installed_binary_name)
            if [ -z "$installed_binary" ]; then
                echo "无法从 systemd 服务中读取 Hysteria2 二进制文件名。"
                exit 1
            fi
            if [ -z "$current_listen_value" ]; then
                echo "无法从配置文件中读取 Hysteria2 监听配置。"
                exit 1
            fi
        
            # 提示用户输入新的监听端口、端口跳跃范围和密码。
            echo ""
            read -p "请输入新的监听端口（直接回车保持当前值 [$current_port]）：" new_port
            [ -z "$new_port" ] && new_port=$current_port
            if ! is_valid_port "$new_port"; then
                echo "监听端口格式无效，请输入 1-65535 之间的单端口。"
                exit 1
            fi
            echo ""
            read -p "请输入新的端口跳跃范围（示例 20000-50000，直接回车保持当前值 [$current_hop_range]，输入 关闭 可停用）：" new_hop_range
            if [ -z "$new_hop_range" ]; then
                new_hop_range=$current_hop_range
            elif [ "$new_hop_range" = "关闭" ]; then
                new_hop_range=""
            elif ! is_valid_port_range "$new_hop_range"; then
                echo "端口跳跃范围格式无效，请输入起始端口小于结束端口的端口范围。"
                exit 1
            fi
            echo ""
            read -p "请输入新的密码（直接回车保持当前值 [$current_password]）：" new_password
            [ -z "$new_password" ] && new_password=$current_password
            echo ""

            listen_value="$new_port"
            client_port="$new_port"
            if [ -n "$new_hop_range" ]; then
                listen_value="$new_hop_range"
                client_port=$(get_first_port "$new_hop_range")
            fi

            # 更新监听配置和密码。
            sed -i -E "s/^listen: :.*/listen: :${listen_value}/" config.yaml
            awk -v new_password="$new_password" 'BEGIN{updated=0} !updated && /^[[:space:]]*password:/ { print "  password: " new_password; updated=1; next } { print }' config.yaml > config.yaml.tmp && mv config.yaml.tmp config.yaml

            # 停止旧服务，重写 systemd 服务后再启动。
            systemctl stop hysteria
            pkill -f 'hysteria*'
            write_systemd_service "$installed_binary"
            systemctl daemon-reload
            systemctl start hysteria

            # 输出客户端导入链接。
            PUBLIC_IP=$(curl -s https://api.ipify.org)
            print_client_links "$new_password" "$PUBLIC_IP" "$client_port" "$new_hop_range"
            exit 0
            ;;
        3)
            # 卸载并删除服务文件。
            systemctl stop hysteria
            systemctl daemon-reload
            rm -rf /root/hysteria
            pkill -f 'hysteria'
            systemctl disable hysteria > /dev/null 2>&1
            rm /etc/systemd/system/hysteria.service
            echo "Hysteria 卸载成功！"
            echo ""
            exit 0
            ;;
        *)
            echo "选项无效。"
            exit 1
            ;;
    esac
fi

# 安装缺失依赖。
install_required_packages

# 检查操作系统和 CPU 架构。
OS="$(uname -s)"
ARCH="$(uname -m)"

# 根据系统架构确定 Hysteria2 二进制文件名。
BINARY_NAME=""
case "$OS" in
  Linux)
    case "$ARCH" in
      x86_64) BINARY_NAME="hysteria-linux-amd64";;
      386) BINARY_NAME="hysteria-linux-386";;
      amd64) BINARY_NAME="hysteria-linux-amd64";;
      aarch64) BINARY_NAME="hysteria-linux-arm64";;
      arm64) BINARY_NAME="hysteria-linux-arm64";;
      mipsle) BINARY_NAME="hysteria-linux-mipsle";;
      s390x) BINARY_NAME="hysteria-linux-s390x";;
      amd64-avx) BINARY_NAME="hysteria-linux-amd64-avx";;
      arm) BINARY_NAME="hysteria-linux-arm";;
      armv5) BINARY_NAME="hysteria-linux-armv5";;
      mipsle-sf) BINARY_NAME="hysteria-linux-mipsle-sf";;
      *) echo "不支持的 CPU 架构"; exit 1;;
    esac;;
  *) echo "不支持的操作系统"; exit 1;;
esac


# 下载 Hysteria2 二进制文件。
mkdir -p /root/hysteria
cd /root/hysteria
wget -q "https://github.com/apernet/hysteria/releases/latest/download/$BINARY_NAME"
chmod 755 "$BINARY_NAME"

# 创建自签名 TLS 证书。
openssl ecparam -genkey -name prime256v1 -out ca.key
openssl req -new -x509 -days 36500 -key ca.key -out ca.crt -subj "/CN=bing.com"

# 读取安装参数。
echo ""
read -p "请输入监听端口（直接回车随机生成）：" port
[ -z "$port" ] && port=$((RANDOM + 10000))
if ! is_valid_port "$port"; then
    echo "监听端口格式无效，请输入 1-65535 之间的单端口。"
    exit 1
fi

echo ""
read -p "请输入端口跳跃范围（示例 20000-50000，直接回车不启用）：" hop_range
if [ -n "$hop_range" ] && ! is_valid_port_range "$hop_range"; then
    echo "端口跳跃范围格式无效，请输入起始端口小于结束端口的端口范围。"
    exit 1
fi

echo ""
read -p "请输入密码（直接回车随机生成）：" password
[ -z "$password" ] && password=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | fold -w 16 | head -n 1)

# 服务端按官方内置端口范围格式监听，未启用端口跳跃时监听单端口。
listen_value="$port"
client_port="$port"
if [ -n "$hop_range" ]; then
    listen_value="$hop_range"
    client_port=$(get_first_port "$hop_range")
fi

# 根据安装参数生成服务端配置。
config_yaml="listen: :$listen_value
tls:
  cert: /root/hysteria/ca.crt
  key: /root/hysteria/ca.key
auth:
  type: password
  password: $password
quic:
  initStreamReceiveWindow: 8388608
  maxStreamReceiveWindow: 8388608
  initConnReceiveWindow: 20971520
  maxConnReceiveWindow: 20971520
  maxIdleTimeout: 60s
  maxIncomingStreams: 1024
  disablePathMTUDiscovery: false
bandwidth:
  up: 1 gbps
  down: 1 gbps
ignoreClientBandwidth: false
disableUDP: false
udpIdleTimeout: 60s
resolver:
  type: udp
  tcp:
    addr: 8.8.8.8:53
    timeout: 4s
  udp:
    addr: 8.8.4.4:53
    timeout: 4s
  tls:
    addr: 1.1.1.1:853
    timeout: 10s
    sni: cloudflare-dns.com
    insecure: false
  https:
    addr: 1.1.1.1:443
    timeout: 10s
    sni: cloudflare-dns.com
    insecure: false"
    
echo "$config_yaml" > config.yaml

# 创建 systemd 服务。
write_systemd_service "$BINARY_NAME"

systemctl daemon-reload
systemctl enable hysteria > /dev/null 2>&1
systemctl start hysteria

# 生成并输出客户端链接。
PUBLIC_IP=$(curl -s https://api.ipify.org)
echo ""
print_client_links "$password" "$PUBLIC_IP" "$client_port" "$hop_range"
