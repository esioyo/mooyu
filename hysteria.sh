#!/bin/bash

# 按字符延迟输出安装器标题。
print_with_delay() {
    text="$1"
    delay="$2"
    for ((i = 0; i < ${#text}; i++)); do
        echo -n "${text:$i:1}"
        sleep $delay
    done
    echo
}

# 显示安装器标题。
echo ""
echo ""
print_with_delay "hysteria2-installer by DEATHLINE | @NamelesGhoul" 0.1
echo ""
echo ""

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

# 校验端口跳跃范围，要求格式为 起始端口-结束端口 且起始端口小于结束端口。
is_valid_port_range() {
    range_value="$1"
    [[ "$range_value" =~ ^[0-9]+-[0-9]+$ ]] || return 1
    range_start=$(echo "$range_value" | cut -d'-' -f1)
    range_end=$(echo "$range_value" | cut -d'-' -f2)
    is_valid_port "$range_start" && is_valid_port "$range_end" && [ "$range_start" -lt "$range_end" ]
}

# 从单端口或端口范围中提取客户端 URI 使用的主端口。
get_first_port() {
    echo "$1" | cut -d'-' -f1
}

# 从端口范围中提取结束端口。
get_range_end() {
    echo "$1" | cut -d'-' -f2
}

# 校验端口跳跃范围必须从主端口开始，保证客户端初始端口和转发规则一致。
is_range_starting_with_port() {
    range_value="$1"
    main_port="$2"
    range_start=$(get_first_port "$range_value")
    [ "$range_start" = "$main_port" ]
}

# 从现有 systemd 服务中读取已安装的 Hysteria2 二进制文件名。
get_installed_binary_name() {
    grep -oP 'ExecStart=/root/hysteria/\K[^ ]+' /etc/systemd/system/hysteria.service 2>/dev/null | head -1
}

# 生成 v2rayN 支持的 Hysteria2 URI，端口跳跃启用时通过 mport 参数传递端口范围。
build_hysteria_uri() {
    uri_password="$1"
    uri_host="$2"
    uri_port="$3"
    uri_hopping_range="$4"

    if [ -n "$uri_hopping_range" ]; then
        echo "hysteria2://$uri_password@$uri_host:$uri_port/?mport=$uri_hopping_range&insecure=1&sni=bing.com"
    else
        echo "hysteria2://$uri_password@$uri_host:$uri_port/?insecure=1&sni=bing.com"
    fi
}

# 写入 systemd 服务，端口跳跃启用时由服务生命周期维护 iptables 转发规则。
write_systemd_service() {
    service_binary="$1"
    service_hopping_enabled="$2"
    service_port="$3"
    service_hopping_range="$4"
    service_redirect_end=$(get_range_end "$service_hopping_range")
    service_redirect_start=$((service_port + 1))

    cat > /etc/systemd/system/hysteria.service <<EOL
[Unit]
Description=Hysteria VPN Service
After=network.target nss-lookup.target

[Service]
User=root
WorkingDirectory=/root/hysteria
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
EOL

    if [ "$service_hopping_enabled" = "true" ]; then
        cat >> /etc/systemd/system/hysteria.service <<EOL
ExecStartPre=-/bin/sh -c 'iptables -t nat -D PREROUTING -p udp --dport ${service_redirect_start}:${service_redirect_end} -j REDIRECT --to-ports ${service_port}'
ExecStartPre=/bin/sh -c 'iptables -t nat -A PREROUTING -p udp --dport ${service_redirect_start}:${service_redirect_end} -j REDIRECT --to-ports ${service_port}'
ExecStopPost=-/bin/sh -c 'iptables -t nat -D PREROUTING -p udp --dport ${service_redirect_start}:${service_redirect_end} -j REDIRECT --to-ports ${service_port}'
EOL
    fi

    cat >> /etc/systemd/system/hysteria.service <<EOL
ExecStart=/root/hysteria/$service_binary server -c /root/hysteria/config.yaml
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=5
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOL
}

# 输出 v2rayN 可导入链接，单端口链接始终可用，端口跳跃链接仅在启用时输出。
print_client_links() {
    link_password="$1"
    link_host="$2"
    link_port="$3"
    link_hopping_enabled="$4"
    link_hopping_range="$5"

    echo "v2rayN 单端口分享链接："
    build_hysteria_uri "$link_password" "$link_host" "$link_port" ""
    echo ""

    if [ "$link_hopping_enabled" = "true" ]; then
        echo "v2rayN 端口跳跃分享链接（客户端不兼容时请使用单端口链接）："
        build_hysteria_uri "$link_password" "$link_host" "$link_port" "$link_hopping_range"
        echo ""
    fi
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
        
            # 读取当前监听端口或端口范围以及认证密码。
            current_port=$(grep -oP 'listen:\s*:\K[0-9]+(-[0-9]+)?' config.yaml | head -1)
            current_primary_port=$(get_first_port "$current_port")
            current_password=$(grep -m 1 'password:' config.yaml | awk -F': ' '{print $2}' | tr -d '[:space:]')
            installed_binary=$(get_installed_binary_name)
            if [ -z "$installed_binary" ]; then
                echo "无法从 systemd 服务中读取 Hysteria2 二进制文件名。"
                exit 1
            fi
        
            # 提示用户输入新的单端口和密码。
            echo ""
            read -p "请输入新的单端口（直接回车使用当前主端口 [$current_primary_port]）：" new_port
            [ -z "$new_port" ] && new_port=$current_primary_port
            if ! is_valid_port "$new_port"; then
                echo "端口格式无效，请输入 1-65535 之间的单个端口。"
                exit 1
            fi
            echo ""
            read -p "请输入新的密码（直接回车保持当前值 [$current_password]）：" new_password
            [ -z "$new_password" ] && new_password=$current_password
            echo ""
            
            # 询问是否启用端口跳跃。
            read -p "是否启用端口跳跃？（y/n，默认 n）：" enable_hopping
            echo ""

            listen_value="$new_port"
            hopping_enabled="false"

            hopping_range=""
            # 端口跳跃启用时，服务端仍只监听主端口，其他端口通过 iptables 转发。
            if [[ "$enable_hopping" == "y" || "$enable_hopping" == "Y" ]]; then
                read -p "请输入端口跳跃范围（例如 20000-30000）：" hopping_range
                if ! is_valid_port_range "$hopping_range"; then
                    echo "端口跳跃范围无效，请使用 起始端口-结束端口，且端口范围必须在 1-65535 内。"
                    exit 1
                fi
                if ! is_range_starting_with_port "$hopping_range" "$new_port"; then
                    echo "端口跳跃范围必须从主端口开始，例如主端口为 $new_port 时应输入 $new_port-结束端口。"
                    exit 1
                fi
                listen_value="$new_port"
                hopping_enabled="true"
                echo "端口跳跃已启用：$hopping_range"
            fi

            # 清理旧版本脚本遗留的无效 hopping 配置，然后更新监听配置和密码。
            sed -i '/^hopping:/,/^[^[:space:]]/ { /^hopping:/d; /^[^[:space:]]/!d; }' config.yaml
            sed -i -E "s/^listen: :.*/listen: :${listen_value}/" config.yaml
            awk -v new_password="$new_password" 'BEGIN{updated=0} !updated && /^[[:space:]]*password:/ { print "  password: " new_password; updated=1; next } { print }' config.yaml > config.yaml.tmp && mv config.yaml.tmp config.yaml

            # 停止旧服务，重写 systemd 服务后再启动。
            systemctl stop hysteria
            pkill -f 'hysteria*'
            write_systemd_service "$installed_binary" "$hopping_enabled" "$new_port" "$hopping_range"
            systemctl daemon-reload
            systemctl start hysteria

            # 输出客户端导入链接。
            PUBLIC_IP=$(curl -s https://api.ipify.org)
            print_client_links "$new_password" "$PUBLIC_IP" "$new_port" "$hopping_enabled" "$hopping_range"
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
read -p "请输入单端口（直接回车随机生成）：" port
[ -z "$port" ] && port=$((RANDOM + 10000))
if ! is_valid_port "$port"; then
    echo "端口格式无效，请输入 1-65535 之间的单个端口。"
    exit 1
fi

echo ""
read -p "请输入密码（直接回车随机生成）：" password
[ -z "$password" ] && password=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | fold -w 16 | head -n 1)

echo ""
read -p "是否启用端口跳跃？（y/n，默认 n）：" enable_hopping
echo ""

# 端口跳跃启用时，服务端仍只监听主端口，其他端口通过 iptables 转发。
listen_value="$port"
hopping_range=""
hopping_enabled="false"
if [[ "$enable_hopping" == "y" || "$enable_hopping" == "Y" ]]; then
    read -p "请输入端口跳跃范围（例如 20000-30000）：" hopping_range
    if ! is_valid_port_range "$hopping_range"; then
        echo "端口跳跃范围无效，请使用 起始端口-结束端口，且端口范围必须在 1-65535 内。"
        exit 1
    fi
    if ! is_range_starting_with_port "$hopping_range" "$port"; then
        echo "端口跳跃范围必须从主端口开始，例如主端口为 $port 时应输入 $port-结束端口。"
        exit 1
    fi
    hopping_enabled="true"
    echo "端口跳跃已启用：$hopping_range"
    echo ""
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

# 创建 systemd 服务，并由 systemd 统一启动、守护和维护端口跳跃规则。
write_systemd_service "$BINARY_NAME" "$hopping_enabled" "$port" "$hopping_range"

systemctl daemon-reload
systemctl enable hysteria > /dev/null 2>&1
systemctl start hysteria

# 生成并输出客户端链接。
PUBLIC_IP=$(curl -s https://api.ipify.org)
echo ""
print_client_links "$password" "$PUBLIC_IP" "$port" "$hopping_enabled" "$hopping_range"
