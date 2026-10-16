# egressvpn 使用教程

按顺序跑一遍就能上线，每步只做这一件事。原理和踩过的坑在 `README.md`，本文只讲操作。

两种出口在员工看来是**同一件事**：都只连 A。`local` 面的流量从 A 自己的网络出去，`via-b` 面的流量由 A 转发到 B、从 B 的网络出去。员工手里没有"连 B"的配置，B 的凭据也不会出现在任何描述文件里。

## 0. 准备清单

| 需要的东西 | 说明 |
|---|---|
| 服务器 A | Ubuntu 22.04/24.04，有公网 IP，内核 ≥ 4.19（要 `xfrm_interface`）。它是 VPN 服务器 |
| 服务器 B（只做 relay 时） | Ubuntu，Linux 就行，不需要 strongSwan |
| A 的服务端证书 | SAN 必须等于员工拨的那个地址；内部 CA 或公共 CA 均可 |
| 一段没用过的私有网池 | 每个 face 一个 `/24`，例如 `10.90.1.0/24`、`10.90.2.0/24` |
| 每个员工的 EAP 口令 | 随机生成，只写在 A 上的 0600 文件里 |

## 1. 打包并安装二进制

开发机上：

```sh
cd egressvpn
VERSION=0.5.7 ./build.sh          # 产出 dist/egressvpn-0.5.7-linux.tar.gz
scp dist/egressvpn-0.5.7-linux.tar.gz root@A:
```

A 上：

```sh
tar -xzf egressvpn-0.5.7-linux.tar.gz && cd egressvpn-0.5.7
uname -m                          # x86_64 用 ./egressvpn；aarch64 用 ./linux-arm64/egressvpn
sudo install -m0755 egressvpn /usr/local/bin/
egressvpn version                 # 必须打印 0.5.7
```

## 2. A 装依赖

一条路是跑包里的 `bootstrap-ubuntu.sh`（它会连配置一起生成，见第 4 步的说明），另一条是手工：

```sh
sudo apt update
sudo apt install -y strongswan strongswan-swanctl libcharon-extauth-plugins \
                    wireguard-tools nftables iproute2
sudo systemctl enable --now strongswan-starter
```

两个必须当场确认的点，否则后面全是白干的活：

```sh
# 1. 插件在位（漏装是最难查的故障：所有客户端死在 IKE_AUTH）
ls /usr/lib/ipsec/plugins/ | grep eap-mschapv2
# 2. Ubuntu 的单元名不是 strongswan
systemctl status strongswan-starter --no-pager | head -3
```

`bootstrap-ubuntu.sh <A的IP> <首个用户名>` 做的事：装依赖 → 建内部 CA 和服务端证书 → 探测出口网卡 → 生成只有 `local` 面的 `egress.yaml` → 随机分配 EAP 口令（**只打印一次**）→ 渲染并把文件摆到各自路径 → 停在 `apply.sh` 之前。

## 3. 证书

已经有 CA 签好的证书就跳到下一步。用内部 CA（员工不装任何 App，靠描述文件里内嵌的 CA 建立信任）：

```sh
sudo mkdir -p /etc/egressvpn/ca && cd /etc/egressvpn/ca

# 根 CA
openssl req -x509 -newkey rsa:3072 -nodes -days 3650 \
  -keyout ca-key.pem -out ca.pem -subj '/CN=Example Root CA'

# 服务端证书：IP 或域名要进 SAN，且必须等于配置里的 server.public-host
openssl req -new -newkey rsa:3072 -nodes -keyout server-key.pem -out server.csr \
  -subj '/CN=203.0.113.10'
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem -days 825 \
  -extfile <(printf 'subjectAltName=IP:203.0.113.10\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n') \
  -out server.pem
```

摆到 strongSwan 只认的位置（`certs =` 要的是**含 `.pem` 的文件名**，且只在 `/etc/swanctl/x509/` 里找）：

```sh
sudo cp server.pem /etc/swanctl/x509/203.0.113.10.pem
sudo cp server-key.pem /etc/swanctl/private/203.0.113.10-key.pem
sudo cp ca.pem /etc/swanctl/x509ca/ca.pem
sudo chmod 600 /etc/swanctl/private/*.pem /etc/egressvpn/ca/ca-key.pem
```

## 4. 写配置表

```sh
sudo mkdir -p /etc/egressvpn/egressvpn-users
sudo cp example/egress.yaml /etc/egressvpn/egress.yaml
```

先只留一个 `local` face 跑通第一跳，再回来加 relay。最小可用配置：

```yaml
server:
  public-host: 203.0.113.10
  cert-file: /etc/swanctl/x509/203.0.113.10.pem
  key-file: /etc/swanctl/private/203.0.113.10-key.pem
  ca-file: /etc/egressvpn/ca/ca.pem
  ca-common-name: Example Root CA
  dns:
    - 1.1.1.1
client:
  display-name: Corp VPN
  organization: Company
  embed-password: false
faces:
  - name: local
    egress: local
    pool: 10.90.1.0/24
    out-interface: ens17        # ip -br a 里那块公网网卡的名字
users:
  - name: alice
    face: local
    password-ref: /etc/egressvpn/egressvpn-users/alice
```

给每个用户生成口令（0600，别写进 YAML）：

```sh
umask 077
tr -dc 'A-Za-z0-9' </dev/urandom | head -c 20 | tee /etc/egressvpn/egressvpn-users/alice; echo
```

要加第二种出口，再补一张 face 和一个 upstream（`example/egress.yaml` 里有完整注释版）：

```yaml
faces:
  # ... 上面的 local 保持不变
  - name: via-b
    egress: relay
    pool: 10.90.2.0/24
    upstream: b
upstreams:
  - name: b
    interface: wgb
    transport: tcp-ssh          # 机房丢 UDP 时用这个；默认 wireguard
    endpoint: 203.0.113.20:22   # tcp-ssh 写 ssh 端口；wireguard 写 51820
    local-ip: 10.91.0.2/32      # A 在第二跳链路上的地址
    remote-ip: 10.91.0.1/32     # B 的地址
    private-key-file: /etc/egressvpn/hop2-b_ed25519
users:
  - name: carol
    face: via-b
    password-ref: /etc/egressvpn/egressvpn-users/carol
```

face 名字 ≤12 字符，pool 之间不能重叠，`transport` 只能是 `wireguard` 或 `tcp-ssh` —— 写错 `validate` 会当场拒绝。

## 5. B 的准备（只做 relay 时）

先决定第二跳怎么承载，判据不是偏好而是**两台机器之间 UDP 通不通**。测法：A 上先开抓包（必须 `-w` 到文件，管道里的行会在进程被 `timeout` 杀掉时丢掉），B 上再发探测包：

```sh
# A 上
sudo timeout 30 tcpdump -i ens17 -nn -w /tmp/probe.pcap 'udp and src <B的IP>'
# B 上（发完再回 A 看 pcap）
for p in 51820 4500 500; do timeout 3 bash -c 'echo x > /dev/udp/<A的IP>/'$p; done
# A 上
sudo tcpdump -nr /tmp/probe.pcap | wc -l
```

结果是 0 而 TCP 通（`nc -vz <A的IP> 22` 能连上）就是机房在单向丢 UDP。**实测结论**（本项目的两台）：同源 40 个 UDP 探测包在 A 的网卡上一个都没收到，同一时刻的 TCP SYN 全部到达并被应答。WireGuard 需要双向 UDP，在这种链路上永远握不上手，而且不会有任何配置检查报错 —— 链路是 up 的、密钥是对的，`conntrack` 只留一条 `[UNREPLIED]`。所以：

- UDP 双向可达 → `transport: wireguard`：B 装 `wireguard-tools`，`wg genkey | tee /etc/wireguard/wg0.key | wg pubkey`，把公钥填进 A 的 `remote-public-key`，`[Peer]` 块用 `render` 输出的 `B-b-peer.txt`。
- UDP 被单向丢 → `transport: tcp-ssh`：B 不装任何东西，把 `render` 输出的 `B-b-peer.txt` **整块按顺序在 B 上执行**（它会装好 B 端隧道脚本、A 的受限公钥、`PermitTunnel yes`、转发开关和持久化 NAT）。

A 端在 `tcp-ssh` 下先生成链路密钥（`ssh-keygen` 会同时写 `.pub`，渲染时要读它）：

```sh
ssh-keygen -t ed25519 -f /etc/egressvpn/hop2-b_ed25519 -N ''
```

B 上无论哪种方式都**不要**给客户端池（`10.90.*`）加任何路由或 NAT —— 它只该看到来自 A 隧道地址（`10.91.0.2`）的流量。

## 6. 校验、渲染、部署

```sh
cd /etc/egressvpn
sudo egressvpn validate -c egress.yaml     # ok: 2 face(s), 1 upstream(s), 2 user(s)
sudo egressvpn render -c egress.yaml -o out
```

按 `README.md` 的表格把 `out/` 里的文件放到各自路径（`apply.sh` 就是按那些路径写的）。放好之后：

```sh
less out/apply.sh        # 确认接口名、表 100、SNAT 地址 —— 它改的是活主机路由
sudo out/apply.sh
sudo out/verify.sh
```

`apply.sh` 幂等，可以重复跑；工具永远不会替你执行它。`verify.sh` 全绿（`all automated checks passed`）才算装上。

## 7. 放行端口与开机持久化

`apply.sh` 不动入站防火墙（那是 A 上原本就在跑的东西）。需要手动放行：

- `udp 500`、`udp 4500`、ESP 协议 50 —— 所有客户端
- `transport: wireguard` 时：`udp 51820`，只允许 A 的公网 IP
- `transport: tcp-ssh` 时：**A 上不需要任何入站规则**（第二跳由 A 主动发起，走的是已有的 ssh 端口）

如果 A 上有宝塔之类的面板防火墙，在它自己的界面里加这几条，别只改 nft —— 面板重载时会把你的规则带走。

路由不需要你操心：按 README 的表把 `routes.sh` 和那两个单元文件摆好后，`apply.sh` 会 enable 并 restart `egressvpn-routes.timer`，之后每分钟重问一次活内核的事实，池路由被接口翻动剪掉时它自己补回来（见第 11 节）。nft 规则不持久，装一个 oneshot 单元重跑 `apply.sh`：

```sh
sudo cp out/apply.sh /usr/local/bin/egressvpn-apply.sh
sudo tee /etc/systemd/system/egressvpn-apply.service >/dev/null <<'EOF'
[Unit]
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/egressvpn-apply.sh

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload && sudo systemctl enable egressvpn-apply.service
```

`tcp-ssh` 的第二跳是 `egressvpn-hop2-<上游名>.service`（`Restart=always`），`apply.sh` 已经 enable 它，不用手工加。

## 8. 发给员工

`out/profiles/<用户>-<face>.mobileconfig` 里账号、服务器地址、算法、CA 都填好了，员工不需要装任何 App。默认 `embed-password: false`，描述文件**不含密码**，只预填用户名。

macOS：

1. 描述文件通过 AirDrop / iCloud / MDM 送到员工手里（**别走邮件和网盘** —— 它含 CA、账号和服务器地址）。
2. 双击 → 系统设置 → 通用 → 描述文件 → 安装（要管理员密码）。
3. 系统设置 → 网络 → VPN → 选 `Corp VPN (<face>)` → 连接。
4. 首次连接输入自己的 EAP 口令。以后 `系统设置 → 网络 → VPN` 或菜单栏图标即可断开。

iOS：设置 → 通用 → VPN 与设备管理 → 描述文件 → 安装；连接在 设置 → 通用 → VPN 与网络 → VPN。

命令行安装（需要管理员）：`sudo profiles install -path <用户>-<face>.mobileconfig`。走 MDM 就上传文件内容。

一个用户一条 face 一个文件；`bob-via-b.mobileconfig` 和 `alice-local.mobileconfig` 的区别只有池地址和出口，员工拨的都是 A。

## 9. 验收

前 8 步做完，拿两台 Mac 各连一个 face：

```sh
# A 上：隧道、SA、转发计数都在
sudo swanctl -l                              # 有 IKE_SA + CHILD_SA，TS 两端都是 0.0.0.0/0
ip -br link show xvlocal | grep UP
sudo out/verify.sh                           # 再跑一遍，连上客户端之后更有意义
```

在员工的 Mac 上（`local` 面和 `via-b` 面各测一次，命令相同、期望值不同）：

```sh
curl -s https://ifconfig.me      # local → A 的公网 IP；via-b → B 的公网 IP
curl -s -o /dev/null -w '%{time_total}\n' https://www.apple.com   # 顺带看延迟
```

**`via-b` 返回 A 的 IP 就是没通过**：说明杀开关没起作用，员工的真实出口是 A。回到 A 上查 `ip rule show | grep lookup\ 100` 和 `wg`/hop2 链路是否 up（`verify.sh` 会直接指出是哪一条）。

最后在 B 上确认它看不到员工：

```sh
# B 上，连 via-b 期间观察
conntrack -L 2>/dev/null | grep -c '10\.90\.'      # 必须是 0
```

四条都对上就验收通过：`local` 出 A、`via-b` 出 B、B 的日志里只有 `10.91.0.2`、`verify.sh` 全绿。

## 10. 日常操作速查

| 要做的事 | 怎么做 |
|---|---|
| 改某人密码 | 覆盖 `password-ref` 的文件 → `render` → 新的 `egressvpn.conf` 放到 `/etc/swanctl/conf.d/` → `sudo swanctl --load-all` |
| 加人 | 同上，然后多发一个 `.mobileconfig` |
| 删人 | 从 `users` 里删掉 → `render` → `--load-all`（实测会输出 `1 unloaded`，真的生效）。立刻断线：`sudo swanctl --terminate --ike-id <IKE_ID>` |
| 看谁在线 | `sudo swanctl -l`（空输出 = 没人连，不是服务坏了） |
| 换第二跳承载 | 只改 `upstreams[].transport` 和 `endpoint` 端口 → `validate` → `render` → 重摆文件 → 重跑 `apply.sh`。`interface` 名字不变，nft 和路由一行都不用改 |
| 只改防火墙/路由 | `sudo nft -f /etc/nftables.d/egress.nft`（先 flush 再按文件重建，是唯一可靠的重来方式） |

## 11. 故障速查

先定症状，再看日志；日志只有 `journalctl -u strongswan-starter` 一处。

| 症状 | 一条命令 | 结论 |
|---|---|---|
| 连上秒断 | `journalctl -u strongswan-starter --since -5min \| grep 'no matching'` | peer config 没匹配上，多半是 `remote.id` 被钉死了（生成为 `%any`，别改） |
| IKE 通、IKE_AUTH 失败 | `grep eap-mschapv2 /proc/$(pgrep -x charon)/maps` | 没输出 = 插件没被**加载**（不是没装）。检查 `/etc/strongswan.d/egressvpn.conf` 里 `load = yes`，然后重启 charon |
| 已连接、没有网络 | `conntrack -L \| grep 10.90.` | 全 `[UNREPLIED]` = 出去了没回来；一条都没有 = 包没进 FORWARD。再看 `ip xfrm policy`，出现通配 `dir out` 就是没走 XFRM 接口 |
| 面板能开、公网没网 | `nft list chain inet egressvpn forward` | 有 `verify.sh` 报的条数不符 = 链顶有人工插的 `drop` 探针。`nft -f /etc/nftables.d/egress.nft` 恢复 |
| 能上网但很慢 | 客户端 `ifconfig ipsec0 \| grep mtu`，`ping -c 20 -D -s 1264 1.1.1.1` | 大包 100% 丢 = MTU/钳制问题。`nft list chain inet egressvpn mssclamp` 的钳制值必须 ≤ 隧道 MTU − 40 **且带范围匹配** |
| 整个 A 上不了网 | `ip route show default` | charon 装了 0/0 进隧道的默认路由 → `install_routes = no` 丢了 |
| via-b 出去还是 A 的 IP | `ip rule show \| grep 'lookup 100'`；`ip -br link show wgb` | 策略路由或第二跳链路没起来。`tcp-ssh` 下先看 `systemctl status egressvpn-hop2-b` |
| 一个 face 全断、另一个正常，连 A 的内网面板都打不开 | `ip -4 route show exact <池> dev xv<face>` | 空 = 池路由随接口翻动被内核剪掉了（不留日志）。此时客户端过 EAP、forward 照样放行，每个回包却都交给默认网关。`journalctl -u egressvpn-routes.service` 看修补记录；timer 一分钟内自愈，没动静就 `systemctl is-active egressvpn-routes.timer` |
| 第二跳永远没有 handshake | B 上 `ping -c2 A的IP`，A 上 `tcpdump -ni ens17 udp port 51820 -c 3` | UDP 单向被丢（本项目实测现象）。改 `transport: tcp-ssh` |

排障时手工 `nft insert` 的计数器**一定要清掉**，按 comment 找 handle 删会漏，直接重放文件。

## 12. 不要做的事

- 不要往 charon 配置里加 `filelog` 段：定义了任何 `filelog`，charon 就不再写 stderr 日志，而 AppArmor 不给它写 `/var/log` 的权限 → 故障现场一个字都没有。
- 不要写 `ip rule replace` —— `ip rule` 没有 `replace` 子命令，`apply.sh` 是 `set -e` 的，会停在 nft 加载之前。
- 不要把 `tuning.mss-clamp` 调到 `tunnel-mtu - 40` 以上（`validate` 会拒），也不要手改成不带范围匹配的 `size set N`：那等于把客户端的 MSS 抬高，大包全丢在客户端。
- 不要开 `embed-password: true` 后走邮件/工单系统分发描述文件。
- 不要在 B 上给 `10.90.*` 加路由或 NAT。
- 不要给 A 加 51820 的入站规则来"修" tcp-ssh 的第二跳 —— 那个模式下 A 是发起方。
- 不要 `systemctl disable egressvpn-routes.timer`：指向某块网卡的 IPv4 路由会随该网卡下线被内核剪掉且不留日志，timer 是唯一会把它补回来的东西。
- 本工具不做流量伪装 / DPI 规避；这类需求要先过公司合规。
