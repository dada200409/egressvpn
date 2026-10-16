# egressvpn

在一台 Ubuntu 服务器（A）上渲染 IKEv2 VPN：员工用账号密码连接后，流量从 **A 自己的网络**出口，或从**中转服务器 B 的网络**出口。B 的凭据只存在于 A 上，员工看不到；relay 流量在 A 上做 SNAT，所以 B 的日志里只有 A 的隧道地址。

A 上的 Go 二进制**只渲染配置文件，不转发任何流量**，也不碰内核。数据面全部是 strongSwan + nftables + WireGuard。

想直接照着上线就读 `TUTORIAL.md`（按步骤跑一遍 + 员工接入 + 验收）；本文讲配置项的含义和真机上校对过的细节。

## 打包

在开发机（macOS 也可以）上：

```sh
./build.sh                      # 产出 dist/egressvpn-<时间戳>-linux.tar.gz
VERSION=1.4.0 ./build.sh        # 固定版本号，egressvpn version 会打印它
```

脚本交叉编译 linux/amd64 和 linux/arm64，`CGO_ENABLED=0`：否则二进制会链接本机 libc，到服务器上直接跑不起来。tar 包内含两个架构、示例配置、本文和 `TUTORIAL.md`。

```sh
scp dist/egressvpn-*-linux.tar.gz ubuntu@A:
ssh ubuntu@A 'tar -xzf egressvpn-*-linux.tar.gz && cd egressvpn-*/ && sudo install -m0755 egressvpn /usr/local/bin/'
egressvpn version
```

不确定架构就用 `uname -m`：`x86_64` → 根目录的 `egressvpn`，`aarch64` → `linux-arm64/egressvpn`。

## 装依赖（A 上）

想一条龙就跑包里的 `bootstrap-ubuntu.sh`（下面是它做的事，逐步手工做也行）：

```sh
sudo ./bootstrap-ubuntu.sh 203.0.113.10 alice
```

它装依赖、建内部 CA 和服务端证书（IP 写进 SAN，客户端靠描述文件里内嵌的 CA 校验）、探测出口网卡、生成一份只有 `local` 一面的 `egress.yaml`、随机分配一个 EAP 口令（只打印一次），渲染并安装到各目标路径，最后**停在这里**——改路由和防火墙的 `apply.sh` 要你自己看过再跑 `egressvpn-apply.sh`。中转出口（B）不在它范围内，那需要 B 的公钥和地址，见下面"配置表"。

```sh
sudo apt update
sudo apt install -y strongswan strongswan-swanctl libcharon-extauth-plugins \
                    wireguard-tools nftables iproute2
```

`libcharon-extauth-plugins` 提供 `eap-mschapv2` 插件。**这个包漏装是最难查的故障**：IKE_SA 一路正常，所有客户端死在 IKE_AUTH，日志只有一句 "no matching authentication policy"。Ubuntu 20.04 及更早叫 `libcharon-extra-plugins`。

验证插件在位（`verify.sh` 也会查）：

```sh
ls /usr/lib/ipsec/plugins/ | grep eap-mschapv2
```

启动服务时注意 **Ubuntu 没有 `strongswan.service`**：单元名是 `strongswan-starter.service`（20.04 及更早是 `ipsec.service`）。`apply.sh` 会自己按 `strongswan-starter` → `ipsec` 的顺序找。

```sh
sudo systemctl enable --now strongswan-starter
```

**光装包不够。** Debian/Ubuntu 的 `strongswan.conf` 里写死了 `charon.load_modular = yes`：插件必须在 `charon.plugins.<名字>.load = yes` 里点名才会被加载。而发行版只给一部分插件随包发了 `/etc/strongswan.d/charon/*.conf`，`eap-mschapv2`、`eap-identity`、`error-notify` 这些**没有**——`libcharon-extauth-plugins` 装好了，`.so` 静静躺在 `/usr/lib/ipsec/plugins/` 里，charon 从不加载它，客户端依然死在 IKE_AUTH。`render` 生成的 `charon-snippet.conf` 就是来点名的，装到 `/etc/strongswan.d/egressvpn.conf` 后要**重启** charon（配置只在启动时读）。

确认到底加载没有——别看 `swanctl --list-algs`，它只列加密算法，永远看不到 EAP：

```sh
grep -o 'libstrongswan-eap-mschapv2\.so' /proc/$(pidof charon | cut -d' ' -f1)/maps
```

另外，`apt install` 不会重建被删掉的 `/etc/strongswan.d/charon/*.conf`（它们是 conffile，装过就不会再写）。如果 charon 起不来、报 `unmet dependency: NONCE_GEN` 之类的缺插件错误，先 `dpkg -V libstrongswan` 看有没有一堆 `missing`，再用下面这条补齐：

```sh
sudo apt-get install -y --reinstall -o Dpkg::Options::=--force-confmiss \
     libstrongswan libstrongswan-standard-plugins libstrongswan-extra-plugins \
     strongswan-libcharon strongswan-charon strongswan-starter strongswan-swanctl
```

## 证书

服务端证书必须让客户端信任。要么用内部 CA 签一张（推荐的 `.mobileconfig` 里会内嵌这个 CA），要么用公共 CA。

配置文件里的 `cert-file` / `key-file` / `ca-file` 只是路径声明，但有一条硬约束：**strongSwan 的 `certs =` 要的是文件名（含 `.pem` 扩展名），并且只在 `/etc/swanctl/x509/` 里找**。写成去掉扩展名的形式不会报"找不到证书"，而是报 `loading certs certificate '/etc/swanctl/x509/vpn.example.com' failed: No such file or directory`，然后整个 connection 加载失败——它是被当**文件路径**用的，不是证书标识。所以证书放在别处时，要么改成这样的路径：

```
/etc/swanctl/x509/vpn.example.com.pem        # 服务端证书（leaf + 中间 CA）
/etc/swanctl/private/vpn.example.com-key.pem # 私钥，0600
/etc/swanctl/x509ca/ca.pem                   # 根 CA
```

要么保持配置文件里的自定义路径，把文件软链到 `/etc/swanctl/x509/`。私钥权限收紧：`sudo chmod 600 /etc/swanctl/private/*.pem`。

## B 上的准备

第二跳有两种承载方式，`upstreams[].transport` 选一种：

**`transport: wireguard`（默认）** —— B 只需要 WireGuard，不需要 strongSwan：

```sh
sudo apt install -y wireguard-tools
```

在 B 上生成密钥对，公钥填进 A 的配置表，私钥留在 B：

```sh
wg genkey | tee /etc/wireguard/wg0.key | wg pubkey
```

在 B 上建 `wg0`，把 `render` 输出的 `B-<upstream名字>-peer.txt`（上游叫 `b` 就是 `B-b-peer.txt`）整块追加进 `/etc/wireguard/wg0.conf` 的 `[Peer]`，并打开转发：

```sh
echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-wg0-forward.conf
sudo sysctl --system
sudo systemctl enable --now wg-quick@wg0
```

B 的防火墙要放行 A 的公网 IP 到 `udp 51820`。B 上**不要**给客户端池做任何路由或 NAT —— 它只该看到来自 A 隧道地址的流量。

**`transport: tcp-ssh`** —— 给"两台服务器之间 UDP 单向被丢"的机房用的。这个不是理论问题：实测从 B 向 A 的 51820/4500/500/443/53 发 40 个 UDP 包（B 的 `ens17` TX 计数证明发出去了），A 的 `ens17` 抓包**一个都没收到**，而同一时刻同源的 TCP SYN 全部到达并被应答。WireGuard 需要双向 UDP，所以它永远握不上手，且没有任何一条配置检查会报错——链路是 up 的、密钥是对的、`conntrack` 只留一条 `[UNREPLIED]`。

这种方式下 B 不装 WireGuard：把 `B-<upstream名字>-peer.txt` 整块按顺序在 B 上执行即可，它会装好 B 端的隧道脚本、A 的公钥（受限 `command=` + `from=`）、`PermitTunnel yes`、转发开关和持久化的 NAT 单元。A 端渲染出三个文件，按表里的路径放好，剩下交给 `apply.sh`：

```sh
# A 上，只在第一次
ssh-keygen -t ed25519 -f /etc/egressvpn/hop2-b_ed25519 -N ''
```

链路的加密由 ssh 自己做，所以 B 的凭据同样不会出现在任何客户端描述文件里。代价是这条链是单条 TCP 流：A↔B 有 RTT 的时候，链式出口每个请求都要多付一次往返延迟，这个和承载方式无关，换回 WireGuard 也一样。

## 配置表

`egress.yaml`（示例见包内 `example/egress.yaml`）。两张 face 对应用户说的两种出口：

```yaml
faces:
  - name: local
    egress: local          # 从 A 自己的网络出去
    pool: 10.90.1.0/24     # 这个出口的客户端地址段
    out-interface: eth0
  - name: via-b
    egress: relay          # 从 B 的网络出去
    pool: 10.90.2.0/24
    upstream: b            # 指向下面某个 upstream
```

写的是 YAML 的子集：嵌套映射、块列表、标量、`#` 注释。flow 写法（`{ }`、`[ ]`）、锚点 `&`/`*`、折叠标量 `|`/`>`、Tab 缩进都会**直接报错**，同样报错的还有拼错的键和重复的键——这份配置生成的是防火墙规则和路由，"静默按另一种意思解析"是不能接受的。要用完整 YAML 就把 `internal/yamlite` 换成 `gopkg.in/yaml.v3`，只有 `internal/config/config.go` 的 `Load` 和 struct tag 需要动。

`server.inbound-interface` 是客户端 ESP 到达的那块网卡，每个 face 的 XFRM 接口都挂在它下面（`xv<face>`）。单网卡机器不用写，默认取第一个 `egress: local` face 的 `out-interface`；客户端从另一块网卡进来的时候才需要显式写。face 名字限 12 个字符，因为内核接口名上限是 15（`IFNAMSIZ`），截断会让 `apply.sh` 里的路由指向一个不存在的设备。

`pool` 子网是唯一的判别依据：nftables 规则和策略路由都按它匹配，所以两个 face 的 pool 不能重叠，`validate` 会拒绝重叠的配置。

第二跳在 `upstreams` 里：

```yaml
upstreams:
  - name: b
    interface: wgb             # A 上的第二跳设备名；两种 transport 都用它
    transport: tcp-ssh         # 默认 wireguard；机房丢 UDP 的时候改这个
    endpoint: 203.0.113.9:22   # wireguard 是 host:51820，tcp-ssh 必须是 host:ssh端口
    local-ip: 10.91.0.2/32     # A 在这条点对点链路上的地址
    remote-ip: 10.91.0.1/32    # B 的地址
    private-key-file: /etc/egressvpn/hop2-b_ed25519  # wg 私钥 或 ssh 私钥（内容永不进渲染结果）
    ssh-user: root             # 仅 tcp-ssh
    # remote-public-key: ...   # 仅 wireguard；tcp-ssh 写了会报错，因为它根本不被使用
```

`tcp-ssh` 需要 `private-key-file` 这个文件**存在**，并且渲染时会读它的 `.pub` 兄弟文件（`ssh-keygen` 自动写）来生成 B 的 `authorized_keys` 行——缺了它 B 端那段就是半成品。`interface` 在两种方式下都是同一个名字，`egress.nft` 的 `oifname`、表 100 的默认路由、每个 face 的杀开关都不区分承载方式，所以换 transport 只是换链路，不改路由。

`tuning` 里三个 MTU 相关的键各管一段，不要混：`tunnel-mtu`（默认 1280）是第一跳 IKE 隧道的 MTU，macOS 客户端的 `ipsec0` 自己就是 1280、且不会要更大的值，A 上的 `xv<face>` 跟着它；`mss-clamp`（默认 `tunnel-mtu - 40`）是钳制后的 MSS，`validate` 会拒绝超过 `tunnel-mtu - 40` 的值，因为那等于把客户端的 MSS 抬高、大包全丢在客户端；`mtu`（默认 1380）只管第二跳的 WireGuard 链路。

密码不要写在配置表里。用 `password-ref` 指向一个文件（0600）或环境变量：

```yaml
users:
  - name: alice
    face: local
    password-ref: /etc/egressvpn/eap/alice
  - name: carol
    face: via-b
    password-ref: env:CAROL_EAP_PASSWORD
```

改完先校验再渲染：

```sh
sudo egressvpn validate -c /etc/egressvpn/egress.yaml
```

## 渲染并部署

```sh
sudo mkdir -p /etc/egressvpn
cd /etc/egressvpn && sudo egressvpn render -c egress.yaml -o out
```

`out/` 里的文件要放到这些位置（`apply.sh` 就是按这些路径写的）：

| 渲染出的文件 | 放到 A 的 | 权限 |
|---|---|---|
| `egressvpn.conf` | `/etc/swanctl/conf.d/egressvpn.conf` | 0600（含 EAP 口令） |
| `charon-snippet.conf` | `/etc/strongswan.d/egressvpn.conf` | 0644 |
| `egress.nft` | `/etc/nftables.d/egress.nft` | 0644 |
| `sysctl.conf` | `/etc/sysctl.d/99-egressvpn.conf` | 0644 |
| `routes.sh` | `/usr/local/sbin/egressvpn-routes.sh` | 0755 |
| `egressvpn-routes.service` | `/etc/systemd/system/egressvpn-routes.service`（文件名即单元名） | 0644 |
| `egressvpn-routes.timer` | `/etc/systemd/system/egressvpn-routes.timer` | 0644 |
| `wgb.conf` | `/etc/wireguard/wgb.conf`（文件名就是 `<接口名>.conf`，`apply.sh` 按接口名去读）—— 仅 `transport: wireguard` | 0600 |
| `hop2-<上游名>-runner.sh` | `/usr/local/sbin/egress-hop2-<上游名>.sh` —— 仅 `tcp-ssh` | 0755 |
| `hop2-<上游名>.service` | `/etc/systemd/system/egressvpn-hop2-<上游名>.service` —— 仅 `tcp-ssh` | 0644 |
| `hop2-<上游名>_ssh_config` | `/etc/egressvpn/hop2-<上游名>_ssh_config` —— 仅 `tcp-ssh` | 0600 |
| `profiles/*.mobileconfig` | 分发给员工 | 0600 |

**`apply.sh` 不会被本工具执行，这是有意的。** 它改的是活主机上的路由和防火墙。先读一遍再手动跑：

```sh
less out/apply.sh          # 确认接口名、策略路由表号、SNAT 地址
sudo out/apply.sh
sudo out/verify.sh
```

`apply.sh` 是幂等的（`ip link show || ip link add`、`replace` 而不是 `add`），可以直接在开机时重跑。路由本身不由 `apply.sh` 持有：链接、地址、池路由和表 100 的规则都写在 `routes.sh` 里，`apply.sh` 只是调用它，之后 `egressvpn-routes.timer` 每分钟再调一次。

这一步是因为一个真机事故：指向某块网卡的 IPv4 路由会随该网卡的下线/注销被内核剪掉，而且不留任何日志。XFRM 接口被周围一切都牵动——第二跳单元重启、strongSwan reload、机房侧链路翻动。这里的实测结果是 `10.90.1.0/24 dev xvlocal` 消失了几小时，期间客户端照常通过 EAP、forward 规则照样放行、`swanctl -l` 完全健康，但每一个回包都被交给默认网关黑洞掉，表现为"连上了，没有网，连内网面板都进不去"。一次性脚本救不了这个，所以放到了 timer 上：每个块只问一个关于活内核的事实，事实没错就什么都不做，一个正常的分钟不产生任何输出。每次动手修补都会写进 `journalctl -u egressvpn-routes.service`，所以"什么时候掉过路由"是查得到的。

nftables 规则不持久，所以要么交给 A 已有的开火墙机制，要么装一个 oneshot 单元：

```ini
# /etc/systemd/system/egressvpn-apply.service
[Unit]
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/egressvpn-apply.sh   # 把 out/apply.sh 复制到这个路径

[Install]
WantedBy=multi-user.target
```

## 分发客户端配置

`out/profiles/<用户>-<face>.mobileconfig` 是给 macOS/iOS 系统设置里"添加 VPN 配置描述文件"用的，账号、服务器地址、算法、CA 都填好了，员工双击安装即可，不需要装任何 App。

默认 `embed-password=false`，所以描述文件里**不含密码**，只会预填用户名，员工首次连接时输入。要免密分发就把 `<client><embed-password>` 设成 `true`——那时描述文件本身等于凭据，别走邮件、网盘或工单系统，且改一次密码就要重发一次。

分发方式任选：双击安装、iCloud/AirDrop，或 `sudo profiles install -path out/profiles/alice-local.mobileconfig`（需要管理员）。走 MDM 就上传文件内容。

## 放行端口（A 的入站防火墙）

`apply.sh` 不生成入站规则，因为那属于 A 上原本就在跑的防火墙。需要手动放行：

- `udp 500`、`udp 4500`、ESP 协议 50 —— 所有客户端
- `transport: wireguard`：`udp 51820`，仅对 A 的公网 IP —— hop 2 的 WireGuard
- `transport: tcp-ssh`：**A 上一跳 2 都不需要放行**，第二跳由 A 主动发起走已有的 ssh 端口；B 侧要的是 `PermitTunnel yes`（`B-<上游名>-peer.txt` 会装）

`apply.sh` 末尾的注释会按你配置的 transport 把上面这些列出来，照着它放行。A 上如果跑着面板防火墙（宝塔之类），要在面板自己的界面里加规则，否则面板重载时会带走你手工塞的 nft 规则。

## 验证

`verify.sh` 检查 swanctl 是否装好、`eap-mschapv2` 插件在不在**并且真的被运行中的 charon 加载了**、nft 规则能否重新编译、connection 有没有进到 charon、第二跳链路是否已经建立（`wireguard` 看 `latest-handshakes`，`tcp-ssh` 看 systemd 单元活着并且能 ping 通 B 的隧道地址）、策略路由是否生效、每个 face 的 forward/mssclamp 条数有没有和生成文件一致、钳制是不是只降不升、`xv<face>` 的 MTU 对不对。另外两条它无法自动化，必须人工确认：

1. relay 用户连上后 `curl ifconfig.me` 返回的是 **B** 的地址，不是 A 的。
2. B 的日志里任何时刻都不出现客户端池地址（`10.90.*`）。

生成的文本里有几处是拿真机（Ubuntu 24.04 / strongSwan 5.9.13 / nft 1.0.9 / kernel 6.8）校对过的，改动前请留意：

- **`ip rule` 没有 `replace` 子命令**（只有 add / delete / change / get，`ip route` 才有 replace）。`apply.sh` 是 `set -e` 的，写错这一步会当场停在 nft 加载和 `swanctl --load-all` 之前，机器看着"部署过了"其实是半套。幂等的写法是先 `ip rule del priority N 2>/dev/null || true` 再 `ip rule add priority N from <pool> lookup 100`。
- `/etc/wireguard/<接口名>.conf` 是 **`wg setconf` 的文件，不是 wg-quick 的文件**：`Address`、`MTU` 这两个键 `wg setconf` 不认，会直接 `Line unrecognized: Address=10.91.0.2/32` 把 `apply.sh` 打断；地址和 MTU 由 `apply.sh` 用 `ip -4 address replace` / `ip link set mtu` 来做。故意不给 `wg-quick` 用：peer 里的 `AllowedIPs = 0.0.0.0/0` 交给 wg-quick 会变成 A 自己的默认路由，把主机流量整条拽进链路。B 那一侧反过来——它用 wg-quick，所以 `[Interface]` 里要写 `Address`，而 `PrivateKeyFile` 在 wg-quick 里同样不认（它也把未知键转给 `wg setconf`），必须写 inline 的 `PrivateKey`。
- nft 的 MSS 选项叫 `maxseg`、可写的成员叫 `size`，`tcp option mss clamp value` 直接编译不过。**钳制必须写成"只降不升"**：`tcp option maxseg size <值+1>-65535 tcp option maxseg size set <值>`。不带范围匹配的 `size set N` 是**无条件改写**，客户端本来只敢 advertise 1240，它会把 1340 塞回去，对端于是发 1380 的包，客户端隧道口（macOS 实测 1280）整个丢掉——症状是"能连、能上网、就是很慢"，ping 得通而大流量全军覆没（payload 1280 丢 0%，1292 丢 100%）。两个方向都要钳：客户端的 SYN 决定对端能发多大的下载段，对端的 SYN-ACK 决定客户端能发多大的上传段，只钳前者遇到 MTU 更大的 Windows 客户端就会漏。
- connection 里是 `reauth_time`，没有 `reauth` 这个键；`local<1>`/`remote<1>` 合法，但 `children<1>` 非法（`children` 是带名字的字典）。写错一个键 strongSwan 不会忽略，而是整段 config 丢弃、一条 connection 都加载不了。
- **全隧道要显式写 `local_ts = 0.0.0.0/0` 和 `remote_ts = 0.0.0.0/0`**，省掉它们不是全隧道。两者的默认值是 `dynamic`，strongSwan 会替换成隧道外层地址和客户端的虚拟 IP：真机上协商出来的是 `10.0.1.2/32 === 10.90.1.1/32`，客户端显示"已连接"、路由表却一条 VPN 路由都不加，流量全走本机网络。判断方法：`swanctl -l` 看 TS，两端都该是 `0.0.0.0/0`。
- **但只有 0/0 还不够，转发型服务器必须用 XFRM 接口（`if_id_in`/`if_id_out`）**。这一条是"连上了但没网络"的真正原因：策略式 IPsec 在 `remote_ts = 0.0.0.0/0` 时会在主策略库里插一条通配的 `src 0.0.0.0/0 dst 0.0.0.0/0 dir out`，凡是这台机器转发的包——包括客户端已经 masquerade 过的包，也包括 A 自己的包——都命中它、被重新加密塞回同一条隧道。实测现象完全对得上：客户端包能到 FORWARD 并被 SNAT，`conntrack -L` 里池地址全是 `[UNREPLIED]`，同时 A 自己访问公网也一起挂掉。
  解法是给每个 face 建一个 XFRM 接口（`ip link add name xv<face> type xfrm dev <inbound-interface> if_id N`），child 里写对应的 `if_id_in`/`if_id_out`，SA 和策略就绑到这个设备上，"什么流量进隧道"重新由路由决定；`apply.sh` 再补 `ip route replace <pool> dev xv<face>`。三个配套坑：`charon.install_routes` 必须关掉（否则 0/0 会变成一条走 xfrm 设备的默认路由）、`net.ipv4.conf.xv<face>.forwarding = 1` 必须按接口打开（解密后的包 iif 就是这个设备，只开 `conf.all` 不够）、内核要 ≥ 4.19 且有 `xfrm_interface` 模块。`xfrm` 设备的 MTU 用 `tuning.tunnel-mtu`（默认 1280，macOS 自己就是这么定的），它和 `tuning.mss-clamp`（默认 `tunnel-mtu - 40`，`Validate()` 拒绝更大的值）是同一件事的两半：设备决定隧道里塞得下多大的包，钳制决定对端别发那么大的包。`tuning.mtu` 只管第二跳的 WireGuard 链路，和隧道口无关。
- `/etc/strongswan.d/egressvpn.conf` 是**一份合并好的覆盖文件**，插件 `load = yes` 和 `install_routes = no` 都在里面。这个文件是顶层 include，谁"只改一个键"而整份重写它，重启后 charon 就没有 eap-mschapv2 了，日志里是 `loading EAP_MSCHAPV2 method failed`、客户端一律 `EAP/FAIL`（真机上踩过，表现是"VPN 都连不上了"）。确认插件到底加载没有，只看 `/proc/$(pgrep -x charon)/maps` 里有没有 `libstrongswan-eap-mschapv2.so`（插件名里的连字符在文件名里也是连字符）。
- 客户端的 IKE ID **不参与匹配**（生成的是 `id = %any`）。macOS/iOS 在没有 Local Identifier 时拿本机 IP 当 IDi（实测是 `172.20.10.53` 这种热点地址），把 `remote.id` 钉成用户名会在检查口令之前就先 `no matching peer config found` 拒掉，表现就是"连上秒断"。真正认证的是 EAP 用户名。
- `systemctl restart strongswan-starter` 之后一定要 `swanctl --load-all`：starter 只负责拉起 charon，不会自己去读 `/etc/swanctl`，漏掉这步机器看着健康、连接数为 0。

## 排障

日志只有一处可看：`journalctl -u strongswan-starter`。**不要往 charon 配置里加 `filelog` 段** —— 一旦定义了任何 `filelog`，charon 就不再创建默认的 stderr 日志，而 Ubuntu 自带的 AppArmor profile（`/etc/apparmor.d/usr.lib.ipsec.charon`）根本没给 `/usr/lib/ipsec/charon` 写 `/var/log` 的权限，文件创建不了，于是"日志一个字都没有的 VPN 故障"。真需要独立文件就同时改 `/etc/apparmor.d/local/usr.lib.ipsec.charon`。

匹配不上的时候开临时调试，看完删掉：

```sh
printf 'charon {\n   debug_cfg = 2\n}\n' > /etc/strongswan.d/zz-debug.conf
systemctl restart strongswan-starter && swanctl --load-all
# 客户端重试一次
journalctl -u strongswan-starter --since -5min | grep 'peer configs matching'
rm /etc/strongswan.d/zz-debug.conf && systemctl restart strongswan-starter && swanctl --load-all
```

那行日志长这样，方括号里就是服务端准备匹配的本地 ID 和客户端实际送来的 IDi：

```
looking for peer configs matching 10.0.1.2[203.0.113.10]...198.51.100.23[172.20.10.53]
no matching peer config found
```

**"已连接但没有网络"不看日志，看计数器**：charon 只记 IKE，数据面的包一个都不记，`journalctl` 里再怎么说 `installed CHILD_SA` 也证明不了有人在转发。三条判据（都在真机上用过）：

```sh
# 1. 客户端的包到底有没有被转发出去 / 有没有回音进来。counter 规则要 insert 到
#    accept/drop 之前，追加到终态规则后面等于没加。
nft insert rule inet egressvpn forward ip saddr 10.90.1.0/24 counter comment probe_out
nft insert rule inet egressvpn forward ip daddr 10.90.1.0/24 counter comment probe_back
# 2. 全 [UNREPLIED] = 包出去了但没有回来；out/back 都是 0 = 包根本没进 FORWARD
conntrack -L | grep 10.90.
# 3. SA 是不是真的绑到了 xfrm 设备（没绑就是通配策略，见"验证"一节）
ip xfrm policy | grep -E 'src|dir|if_id'
```

用完**必须**清掉探针，而可靠的做法不是按 comment 找 handle 删（真机上就这么漏删过一条，之后表现为"面板能开、公网没网"），而是直接重来一遍：`nft -f /etc/nftables.d/egress.nft`，它先 flush 再按文件重建。另一个便宜的旁证是**服务器自己还能不能上网**——A 自己断网而客户端显示已连接，基本就是通配 `dir out` 策略把 A 的流量也加密回隧道了。

**"能上网但很慢"先量隧道口，别猜 CPU**：真机上 2 vCPU 跑满时几乎全 idle、AES-NI 也在，瓶颈却是 MTU。三步（都在 macOS 客户端上跑）：

```sh
ifconfig ipsec0 | grep mtu                                  # macOS 的 IKEv2 口自己就是 1280
for p in 1252 1264; do ping -c 20 -D -s $p 1.1.1.1; done    # -D 不分片，-s 定载荷
```

`payload=1252` 全通、`payload=1264`（inner 1292）全丢，就是路径 MTU 被卡死，跟加密、跟带宽都无关。此时对照 A 上的两件事：`ip -d link show xv<face>` 的 mtu，和 `nft list chain inet egressvpn mssclamp` 里的钳制值——后者必须 ≤ 前者 − 40，而且必须带范围匹配。`verify.sh` 已经把这几条做成自动检查（每个池的 forward 条数、mssclamp 的条数和"只降不升"、xfrm 设备的 MTU），FAIL 的修法都是重跑 `nft -f /etc/nftables.d/egress.nft` 或 `apply.sh`，不要手改内核。

顺带排掉两个假嫌疑人：A 是**转发**角色，`net.core.rmem_max` / `net.ipv4.tcp_rmem` 调的是 A 自己的 socket，对穿过隧道的流量不起作用；`esp-proposals` 从 CBC+HMAC 换成 GCM 只省 CPU，而 CPU 本来就没占用，换它反而要赌 macOS 的算法协商，别当性能手段用。

**第二跳一直握不上手，先证明 UDP 到没到过网卡**。这个故障在所有检查里都是"正常"的：接口 up、密钥正确、`wg show` 只是 `latest-handshakes = 0`、`conntrack` 里一条 `[UNREPLIED]`，因为丢包发生在 A 的 netfilter 之前。判据只有网卡上的抓包（用 `-w` 落地文件再读，管道输出会在 `timeout` 杀进程时丢掉缓冲的行）：

```sh
# A 上开抓包 -> B 上发几个 UDP 探测 -> 回 A 读 pcap
sudo tcpdump -i ens17 -nn -w /tmp/probe.pcap 'udp and src <B的IP>'
# B 上：for p in 51820 4500 500; do timeout 3 bash -c 'echo x > /dev/udp/<A的IP>/'$p; done
sudo tcpdump -nr /tmp/probe.pcap | wc -l
nc -vz <A的IP> 22        # TCP 通而上面是 0，就是机房在单向丢 UDP
```

这个不是理论：实测同源 40 个 UDP 包（B 的网卡 TX 计数证明发出去了）在 A 的 `ens17` 上收到 0 个，同一时刻 TCP SYN 全部到达并被应答。WireGuard 要双向 UDP，所以在这种机房下没有配置能修好它，把那个 upstream 改成 `transport: tcp-ssh`（见"B 上的准备"）。

## 日常运维

改密码 → 覆盖 `password-ref` 指向的文件，重跑 `render`，把新的 `egressvpn.conf` 放到 `/etc/swanctl/conf.d/` 后 `sudo swanctl --load-all`。加用户是同样流程，然后发一个新的 `.mobileconfig`。

删用户也是同样流程，而且**真的生效**：`swanctl --load-all` 会卸载已经不在文件里的 connection（实测输出 `successfully loaded 1 connections, 1 unloaded`）。别去调 `swanctl --flush`，5.9 只有 `--flush-certs`，没有 `--flush`。已经在跑的隧道要立刻断就 `sudo swanctl --terminate --ike-id <他的IKE_ID>`；不干预的话最迟下一次 `reauth_time` 重认证时被拒。

`egress.nft` 可以直接重复 `nft -f`：文件开头先 `table inet egressvpn { }` 再 `flush table inet egressvpn`，所以重新渲染并加载后内核里的规则就是这份文件的内容，不会留下上个池子的 accept（实测连加两次不重复，`nft -c -f` 在 table 还不存在的新机器上也能过）。

**排障时手工 `nft insert` 的计数器/护栏一定要删掉，而且 `flush` 是唯一可靠的重来方式。** 真机上出过一次很难查的事故：调试时 `insert` 到链顶的 `ip saddr <pool> drop` 因为找不到 handle 没删成，从此它压在所有 accept 上面，客户端表现为"面板能开、公网没网"——面板是 A 自己应答的包（走 INPUT 不过 FORWARD），公网流量全在 FORWARD 被这条幽灵规则吃掉，而 `swanctl -l` 里隧道完好、日志一个字都不报错。`verify.sh` 现在会核对内核里每个池的 forward 规则条数是否等于生成文件里的条数，多一条就 FAIL；恢复就一句 `nft -f /etc/nftables.d/egress.nft`。

看谁在连接：`sudo swanctl -l`（空输出就是没人连，别误判成服务坏了）。

## 已知边界

- **YAML 是受限子集**，由 `internal/yamlite` 自己解析（零外部依赖）。换 `gopkg.in/yaml.v3` 只要改 `internal/config/config.go` 的 `Load` 和 struct tag。
- **每个用户一段 connection**，几百个账号会让 `egressvpn.conf` 膨胀、加载变慢。规模上去后要换成 RADIUS + 按 group 匹配，那是另一次改造。
- **EAP-MSCHAPv2 是弱凭据**。在"不装 App、只要账号密码"这个约束下它是 macOS 内置 IKEv2 唯一现实的选择；口令会过线给服务器校验，因此 A 上存着全部明文口令。能接受装客户端时，EAP-TLS（每人一张证书）明显更强。
- hop 2 默认用 WireGuard 而不是嵌套 IPsec，因为两端都是 Linux，没有"客户端不能装东西"的限制，同时避开 IPsec-in-IPsec 的 XFRM 复杂度。**前提是两台机器之间 UDP 双向可达**；机房单向丢 UDP 时它永远不通，这时换 `transport: tcp-ssh`（用 `ssh -w` 的 tun 设备承载同一个 `interface` 名字，路由和 nft 都不变）。代价：这条链是单条 TCP 流，A↔B 有 RTT 时链式出口每个请求多付一次往返（实测 A↔B ~148 ms，且这个延迟和承载方式无关），吞吐上限也由那条流决定。
- 本工具不做任何流量伪装 / 规避 DPI 检测的功能。
