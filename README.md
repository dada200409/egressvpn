# egressvpn

> 一份 YAML → 一整套 strongSwan IKEv2 + nftables 出口部署：员工用账号密码接入，流量按账号从 A 自己的网络出口，或链式经 B 从 B 的网络出口。
>
> Renders a complete strongSwan IKEv2 / nftables egress deployment from one YAML table. Two egress faces per host, per-account routing, chained exit through a second server, and the second server's credential never reaches an employee.

- **控制面是 Go，数据面是内核。** A 上的二进制只渲染配置文件，不转发任何流量、不碰内核、不做任何加密实现，IKE/EAP 全部由 strongSwan 承担。
- **员工侧不装任何 App。** macOS/iOS 内置 IKEv2 + EAP-MSCHAPv2，双击一个 `.mobileconfig` 就完事。
- **出口选择由账号决定，不由客户端决定。** 员工永远只拨 A；"从 B 出去"是 A 做的转发，不是第二条 VPN。

按步骤上线请看 [`TUTORIAL.md`](TUTORIAL.md)。本文是配置项、产物、运维与故障的参考手册。

## 目录

- [它解决什么问题 / 不解决什么问题](#它解决什么问题--不解决什么问题)
- [工作原理](#工作原理)
- [环境要求](#环境要求)
- [快速开始](#快速开始)
- [安装与构建](#安装与构建)
- [命令行参考](#命令行参考)
- [配置参考](#配置参考)
- [渲染产物与放置路径](#渲染产物与放置路径)
- [部署流程](#部署流程)
- [第二跳的两种承载](#第二跳的两种承载)
- [客户端描述文件](#客户端描述文件)
- [入站放行](#入站放行)
- [verify.sh 到底验了什么](#verifysh-到底验了什么)
- [日常运维](#日常运维)
- [故障速查](#故障速查)
- [真机上校对过的细节](#真机上校对过的细节)
- [实测数据](#实测数据)
- [设计决策](#设计决策)
- [安全模型与已知边界](#安全模型与已知边界)
- [代码结构](#代码结构)
- [开发与贡献](#开发与贡献)
- [许可与免责](#许可与免责)

## 它解决什么问题 / 不解决什么问题

**解决**：

| 需求 | 怎么满足 |
|---|---|
| 一批机器要"从指定服务器的网络出去"，且不能装客户端 | IKEv2 + EAP-MSCHAPv2，系统内置 |
| 同一台服务器上要有多个出口，按人区分 | 每个 face 一个独立客户端地址池；nft 规则和策略路由都按池匹配 |
| 二级出口（A→B）要把 B 的凭据藏起来 | B 的私钥/公钥/口令只存在于 A，客户端描述文件里没有任何 B 的信息 |
| 链式出口不能"静默泄漏"到 A 的 IP | relay face 的公网路径只存在于策略路由表 100；二跳断了就丢包，不会回落到主表从 A 出去 |
| 部署要可复现、可审计 | 一条命令渲染出全部文件，`apply.sh` 由人读过之后自己跑 |
| 机房内核剪路由导致的偶发全断 | 60 秒周期的路由 reconcile timer，见[部署流程](#部署流程) |

**不解决 / 明确不做**：

- **流量伪装、规避 DPI 检测**：一行都没有。这类需求应当先过网络/合规审批，不该由工具顺手实现。
- **账号系统**：口令存在 A 本地文件里（`password-ref`），没有 RADIUS/LDAP。每人一段 connection，几百账号以上要改造。
- **多机控制面 / 高可用**：一台 A 一份配置，没有集群、没有分布式状态。
- **IPv6**：只下发 IPv4。客户端会请求 `%any6` 但拿不到 v6 地址，v6 流量继续走它本地网络。这是**已知泄漏**，见[安全模型](#安全模型与已知边界)。
- **NAT 后部署**：A 必须有公网可达的 UDP 500/4500 + ESP。1:1 NAT 可以（证书身份写公网地址即可），纯私有网络不行。

## 工作原理

```
   员工 Mac：内置 IKEv2，配置里只有 A 的地址
                           |
        IKE_SA + IKE_AUTH(EAP-MSCHAPv2)
                           |
   +----------------------------------------------------------+
   | A  203.0.113.10   跳板：唯一承载 VPN 服务端的一段        |
   | charon + 每 face 一个 xv<face> + nft + 策略路由          |
   |                                                          |
   | face local : 10.90.1.0/24 -> xvlocal -> MASQ -> A 出去   |
   | face via-b : 10.90.2.0/24 -> xvvia-b -> ip rule pri 100  |
   |                                     -> table 100 -> wgb  |
   +----------------------------------------------------------+

               hop 2 链路 wgb：B 的凭据只落在这里
             ssh -w 10:10  或  WireGuard
                           |
   +----------------------------------------------------------+
   | B  203.0.113.20   中转出口：员工完全不知道它存在         |
   | 只做 postrouting masquerade，没有任何 10.90.* 路由       |
   +----------------------------------------------------------+

                            v   B 的公网 IP（relay 用户的出口）
```

四个关键机制，缺一不可：

1. **一个 face = 一个地址池 = 一条路由决策。** face 不是策略名，`pool` 子网才是唯一的判别依据：`egress.nft` 按 `ip saddr <pool>` 匹配，relay face 额外建一条 `ip rule priority N from <pool> lookup 100`。两个池重叠 = 规则互相抢，`validate` 直接拒绝。
2. **XFRM 接口（`xv<face>`）承担"什么流量进隧道"。** 转发型服务器上纯策略式 IPsec 会插一条通配 `dir out` 策略，把 A 自己转发的包重新加密塞回同一条隧道；`if_id_in/if_id_out` 把 SA 绑到设备之后，路由重新成为唯一入口判据。
3. **`charon.install_routes = no`。** 装了 0/0 进隧道的默认路由会把整台 A 的出网流量拽进隧道，所以 strongSwan 完全不碰路由表 —— 代价是池路由必须由本工具自己长期负责，这就是 `routes.sh` + timer 存在的原因。
4. **凭据隔离。** relay 用户在 A 上被 SNAT 成 `upstreams[].local-ip`（默认 `10.91.0.2`），所以 B 的日志里任何时刻都不该出现 `10.90.*`；B 的凭据是 A 上的一个 0600 私钥文件，渲染结果和描述文件里都不含它。

## 环境要求

| 组件 | 要求 | 检查 |
|---|---|---|
| OS | Ubuntu 20.04/22.04/24.04（Debian 类似），A 需要 root | `lsb_release -a` |
| 内核 | ≥ 4.19 且有 `xfrm_interface` 模块 | `modprobe xfrm_interface && ls /sys/module/xfrm_interface` |
| strongSwan | ≥ 5.9，必须能加载 `eap-mschapv2` | `ls /usr/lib/ipsec/plugins/ \| grep eap-mschapv2` |
| 包 | `strongswan strongswan-swanctl libcharon-extauth-plugins wireguard-tools nftables iproute2` | 见[快速开始](#快速开始)；`libcharon-extra-plugins` 是 20.04 及更早的包名 |
| B | 只需要 `wireguard-tools`（`transport: wireguard`）或什么都不装（`tcp-ssh`）+ `sshd` 允许 `PermitTunnel` | — |
| 网络 | A 的 UDP 500/4500 + ESP 入站可达；A↔B 的二跳承载可达 | `nc -vz` / [故障速查](#故障速查) |
| 客户端 | 支持 IKEv2 + EAP-MSCHAPv2 即可（macOS/iOS 内置就够，Windows 同理）；**本项目只在 macOS 上实测过** | — |

`egressvpn` 本体是静态链接的单一 ELF（`CGO_ENABLED=0`，无外部 Go 模块），amd64/arm64 都有，不要求目标机装 Go 或匹配 glibc。

## 快速开始

一条龙脚本，装依赖 + 建内部 CA 和服务端证书（IP 写进 SAN）+ 探测出口网卡 + 生成一份只有 `local` 一面的 `egress.yaml` + 随机分配一个 EAP 口令（**只打印一次**）+ 渲染并安装到各目标路径：

```sh
sudo ./bootstrap-ubuntu.sh 203.0.113.10 alice
```

它**停在 `apply.sh` 之前**：不改路由、不加载 nftables。但要清楚它已经动了 strongSwan —— 脚本会 `systemctl restart` charon 并跑 `swanctl --load-all`，也就是连接已经装进活着的 daemon。改路由/防火墙那一步永远由你亲手执行：

```sh
sudo less /etc/egressvpn/out/apply.sh   # 确认接口名、策略路由表号、SNAT 地址
sudo /usr/local/bin/egressvpn-apply.sh
sudo /usr/local/bin/egressvpn-verify.sh
```

脚本不覆盖的情况：已有 CA 会复用（`/etc/egressvpn/ca/`）、第二跳（需要 B 的地址和公钥）、以及入站放行规则（那属于 A 上原本就在跑的防火墙）。手工装依赖与逐条命令见 `TUTORIAL.md`。

## 安装与构建

从 GitHub 安装（需要本机有 Go）：

```sh
go install github.com/dada200409/egressvpn/cmd/egressvpn@latest
```

从源码打包（开发机可以是 macOS）：

```sh
./build.sh                      # 产出 dist/egressvpn-<时间戳>-linux.tar.gz
VERSION=1.4.0 ./build.sh        # 固定版本号，egressvpn version 会打印它
```

`build.sh` 会先 `go build ./...` + `go test ./...`（任一失败即停），再交叉编译 linux/amd64 与 linux/arm64，`CGO_ENABLED=0`：否则二进制链接的是本机 libc，到服务器上直接跑不起来。tar 包内含两个架构、根目录一份 amd64 裸二进制、示例配置、本文、`TUTORIAL.md` 和 `bootstrap-ubuntu.sh`。`COPYFILE_DISABLE=1` 是故意的：macOS 的 bsdtar 会把 Apple xattr 写成 AppleDouble 头，服务器上的 GNU tar 会对每个文件打印 `Ignoring unknown extended header keyword ...`，安装过程满屏警告看着像下载损坏。

```sh
scp dist/egressvpn-*-linux.tar.gz ubuntu@A:
ssh ubuntu@A 'tar -xzf egressvpn-*-linux.tar.gz && cd egressvpn-*/ && sudo install -m0755 egressvpn /usr/local/bin/'
egressvpn version
```

不确定架构就 `uname -m`：`x86_64` → 根目录的 `egressvpn`，`aarch64` → `linux-arm64/egressvpn`。

## 命令行参考

```
egressvpn <command> [flags]
```

| 命令 | 参数（默认） | 作用 |
|---|---|---|
| `validate` | `-c egress.yaml` | 只做结构校验和 `Validate()`，打印 `ok: N face(s), N upstream(s), N user(s)` |
| `render` | `-c egress.yaml`，`-o out` | 校验后把全部产物写进 `-o` 目录，含 `profiles/<用户>-<face>.mobileconfig`；逐个文件打印 `wrote <路径>` |
| `genkey` | — | 输出一对 WireGuard 密钥（私钥标注"keep secret, mode 0600"） |
| `genpsk` | — | 输出一条 base64 PSK |
| `version` | — | 编译期由 `-ldflags -X main.version=` 注入，未注入时是 `dev` |
| `help` / 无参数 / `-h` | — | 打印用法，退出码 0 |

只有 `-c` / `-o` 两个短参，**没有长参数**（`--config` 会报错）。退出码：坏旗标是 **2**（`flag.ExitOnError`），其他错误打印 `error: <消息>` 后是 **1**，成功 0。

`render` 不会执行任何东西，也不联网。它唯一"读本机"的地方：`transport: tcp-ssh` 时要求 `private-key-file` 存在并读它的 `.pub` 兄弟文件来生成 B 的 `authorized_keys` 行。EAP 口令只出现在 `egressvpn.conf` 里，因此那个文件写成 0600（swanctl 没有 `--file` 之类的重定向旗标）。

## 配置参考

配置文件是 YAML 的**受限子集**，由 `internal/yamlite` 自己解析：支持嵌套映射、块列表、标量、`#` 注释。flow 写法（`{ }`、`[ ]`）、锚点 `&`/`*`、折叠标量 `|`/`>`、Tab 缩进、拼错的键、重复的键 —— 全部**直接报错而不是猜**。这份配置生成的是防火墙规则和路由，"静默按另一种意思解析"是不能接受的。时长值接受 `30s` / `5m` / `4h` 或裸秒数（按分钟向下取整，最小 1）；布尔只认 `true` / `false`。

顶层只有六个键：`server` `client` `tuning` `faces` `upstreams` `users`。

### `server`

| 键 | 必填 | 默认 | 说明 |
|---|---|---|---|
| `public-host` | 是 | — | 客户端拨的地址，也是证书身份；1:1 NAT 环境写公网地址而不是网卡地址 |
| `identity` | 否 | `public-host` | strongSwan 侧的本地 ID，必须与服务器证书 SAN 一致 |
| `cert-file` / `key-file` | 是 | — | 路径声明，但**有硬约束**：`certs =` 要的是含 `.pem` 的文件名且只在 `/etc/swanctl/x509/` 里找，见[真机校对](#真机上校对过的细节) |
| `ca-file` | 是 | — | 根 CA；生成客户端描述文件必需 |
| `ca-common-name` | 否 | 从证书读 | 描述文件里钉住签发者；不写则从 `ca-file` 的 CN 推导 |
| `inbound-interface` | 否 | 第一个 `egress: local` face 的 `out-interface` | 客户端 ESP 到达的网卡，每个 face 的 `xv<face>` 挂在它下面 |
| `dns` | 否 | 空 | 下发给客户端的 DNS，例如 `1.1.1.1`、`8.8.8.8` |
| `lan` | 否 | 空 | 不经过公网就能到达的网段，会在 forward 链里单独放行 |

### `client`

| 键 | 默认 | 说明 |
|---|---|---|
| `display-name` | `VPN` | 系统设置里显示的名字 |
| `organization` | `egressvpn` | 描述文件的组织字段 |
| `remote-address` | `server.public-host` | 客户端实际拨的地址；和证书身份不同时（NAT/PAD）才需要显式写 |
| `prefill-username` | `true` | 预填 EAP 身份，员工只输口令 |
| `embed-password` | `false` | `true` 时把口令烘进描述文件 —— 描述文件本身即凭据，改一次口令要重发一次，且不要走邮件/网盘/工单系统 |
| `send-local-identifier` | `false` | 保持 `false`；`remote.id` 是 `%any`，客户端 ID 不参与匹配 |
| `removal-disallowed` | `false` | `true` 时员工无法自行删除该配置（MDM 场景） |

`embed-password: false` **且** `prefill-username: false` 时，描述文件里既没有身份也没有口令，员工两个都要手输 —— 这不是错误，但没有预填的意义了。

### `tuning`

| 键 | 默认 | 约束 | 管什么 |
|---|---|---|---|
| `tunnel-mtu` | `1280` | 576..1500 | 第一跳 IKE 隧道：`xv<face>` 设备的 MTU。macOS 的 `ipsec0` 自己就是 1280 且不会要更大，改大只会让客户端丢掉所有大包 |
| `mss-clamp` | `tunnel-mtu - 40` | 536..1460 **且** ≤ `tunnel-mtu - 40` | 钳制后的 MSS。`Validate()` 拒绝更大的值：nft 的改写是无条件的，抬高等于把大包全丢在客户端 |
| `mtu` | `1380` | — | **第二跳链路的 MTU**，两种承载都用它（`wireguard` 和 `tcp-ssh` 的 `ssh -w` 设备）；与隧道口无关 |
| `ike-proposals` / `esp-proposals` | `aes256-sha256-modp2048` | 生成描述文件时只认 `aes128`/`aes256` | 算法串在这里不校验，`validate` 能过而 `render` 在生成 `.mobileconfig` 时失败 —— 要换 GCM 就别分发描述文件 |
| `dpd-delay` | `30s` | — | 另有硬编码的 `dpd_timeout = 180s` |
| `rekey-time` | `14400s` | — | IKE 重认证周期，也是删号生效的最晚上限 |
| `child-rekey-time` | `3600s` | — | CHILD_SA 重密钥 |
| `wg-port` | `51820` | — | 仅 `transport: wireguard` |
| `wg-keepalive` | `25` | — | 仅 `transport: wireguard`，NAT 后需要 |

### `faces`（出口，一段一个）

```yaml
faces:
  - name: local
    egress: local          # 从 A 自己的网络出去
    pool: 10.90.1.0/24     # 这个出口的客户端地址段
    out-interface: eth0
  - name: via-b
    egress: relay          # 从 B 的网络出去
    pool: 10.90.2.0/24
    upstream: b
```

| 键 | 必填 | 默认 | 约束 |
|---|---|---|---|
| `name` | 是 | — | 全局唯一，**≤ 12 字符**（设备名是 `xv<name>`，内核上限 `IFNAMSIZ`=15；截断会让路由指向不存在的设备） |
| `egress` | 是 | — | 只能是 `local` 或 `relay` |
| `pool` | 是 | — | CIDR，任何两个 face 不能重叠 |
| `out-interface` | 否 | `eth0`（仅 `local`） | `relay` 时忽略 |
| `upstream` | `relay` 必填 | — | 必须指向 `upstreams` 里存在的名字 |

### `upstreams`（第二跳）

```yaml
upstreams:
  - name: b
    interface: wgb             # A 上的二跳设备名；两种 transport 都用它
    transport: tcp-ssh         # 默认 wireguard；机房丢 UDP 时改这个
    endpoint: 203.0.113.20:22  # wireguard 是 host:51820，tcp-ssh 必须是 host:ssh端口
    local-ip: 10.91.0.2/32     # A 在这条点对点链路上的地址（必须是 CIDR）
    remote-ip: 10.91.0.1       # B 的地址（CIDR 或裸 IP 都行）
    private-key-file: /etc/egressvpn/hop2-b_ed25519   # wg 私钥或 ssh 私钥，内容永不进渲染结果
    ssh-user: root             # 仅 tcp-ssh，默认 root
    tunnel-index: 10           # 仅 tcp-ssh，1..999，默认 10+i
    # remote-public-key: ...   # 仅 wireguard
    # psk-file: ...            # 仅 wireguard
```

| 键 | 必填 | 默认 | 说明 |
|---|---|---|---|
| `name` | 是 | — | 唯一；决定 `B-<name>-peer.txt`、`egressvpn-hop2-<name>.service`、`/usr/local/sbin/egress-hop2-<name>.sh` 等名字 |
| `interface` | 否 | `wg-<name>` | **两种承载共用同一个名字**，`egress.nft` 的 `oifname`、表 100 默认路由、每个 face 的杀开关都不区分 transport，所以换承载不改路由 |
| `transport` | 否 | `wireguard` | `wireguard` \| `tcp-ssh` |
| `endpoint` | 是 | — | `wireguard` 走 `net.ResolveUDPAddr`；`tcp-ssh` 要 `host:port`，端口 1..65535 |
| `local-ip` | 是 | — | **必须 CIDR**（`10.91.0.2/32`），裸 IP 会被拒 |
| `remote-ip` | 是 | — | B 的隧道地址，也是 relay 的 SNAT 目标可达性依据 |
| `private-key-file` | 是 | — | `tcp-ssh` 要求文件存在，并读 `.pub` 生成 B 的 `authorized_keys`；`wireguard` 在渲染时读取内容 |
| `remote-public-key` | wg 必填 | — | `tcp-ssh` 写了直接报错（ssh 自己加密，这个键根本不被使用） |
| `psk-file` | 否 | 空 | 仅 `wireguard`；`tcp-ssh` 写了报错 |
| `ssh-user` | 否 | `root` | 仅 `tcp-ssh` |
| `tunnel-index` | 否 | `10 + i` | 仅 `tcp-ssh`，`ssh -w N:N` 的 tun 序号，1..999。故意不用 0：`tun0` 容易和本机已有设备撞名 |

### `users`

```yaml
users:
  - name: alice
    face: local
    password-ref: /etc/egressvpn/eap/alice      # 0600 文件，尾部换行会被剥掉
  - name: carol
    face: via-b
    password-ref: env:CAROL_EAP_PASSWORD        # 从环境变量取
```

`password` 和 `password-ref` 必须给一个（`password` 只为本地测试准备，别提交进版本库）；`face` 必须存在。口令不要写进配置表：`render` 会把它解析出来塞进 `egressvpn.conf`，配置文件本身不该成为凭据的载体。

## 渲染产物与放置路径

```sh
sudo mkdir -p /etc/egressvpn
cd /etc/egressvpn && sudo egressvpn render -c egress.yaml -o out
```

`out/` 里的文件要放到下面这些位置 —— **`apply.sh` 就是按这些绝对路径写的**，所以 `sudo out/apply.sh` 只有在文件已经就位之后才有意义：

| 渲染出的文件 | 放到 A 的 | 权限 | 备注 |
|---|---|---|---|
| `egressvpn.conf` | `/etc/swanctl/conf.d/egressvpn.conf` | 0600 | 含全部 EAP 口令 |
| `charon-snippet.conf` | `/etc/strongswan.d/egressvpn.conf` | 0644 | 合并好的顶层覆盖：插件 `load = yes` + `install_routes = no` |
| `egress.nft` | `/etc/nftables.d/egress.nft` | 0644 | 开头 `table inet egressvpn {}` + `flush table`，可重复 `nft -f` |
| `sysctl.conf` | `/etc/sysctl.d/99-egressvpn.conf` | 0644 | 全局转发 + 每设备 `forwarding/rp_filter=2/accept_local/send_redirects` |
| `routes.sh` | `/usr/local/sbin/egressvpn-routes.sh` | 0755 | 唯一持有链路/地址/池路由/表 100 规则的文件 |
| `egressvpn-routes.service` | `/etc/systemd/system/egressvpn-routes.service` | 0644 | Type=oneshot |
| `egressvpn-routes.timer` | `/etc/systemd/system/egressvpn-routes.timer` | 0644 | `OnBootSec=30s`、`OnUnitActiveSec=60s`、`AccuracySec=15s` |
| `apply.sh` | `/usr/local/bin/egressvpn-apply.sh` | 0755 | **由人读过之后手动执行** |
| `verify.sh` | `/usr/local/bin/egressvpn-verify.sh` | 0755 | 见 [verify.sh](#verifysh-到底验了什么) |
| `<接口名>.conf`（如 `wgb.conf`） | `/etc/wireguard/wgb.conf` | 0600 | 仅 `transport: wireguard`；文件名就是接口名，`apply.sh` 按接口名去读 |
| `hop2-<上游名>-runner.sh` | `/usr/local/sbin/egress-hop2-<上游名>.sh` | 0755 | 仅 `tcp-ssh` |
| `hop2-<上游名>.service` | `/etc/systemd/system/egressvpn-hop2-<上游名>.service` | 0644 | 仅 `tcp-ssh`；Type=simple，`Restart=always RestartSec=5` |
| `hop2-<上游名>_ssh_config` | `/etc/egressvpn/hop2-<上游名>_ssh_config` | 0600 | 仅 `tcp-ssh`；`UserKnownHostsFile` 指向同目录的 `_known_hosts`，靠 `accept-new` 首连落盘 |
| `B-<上游名>-peer.txt` | **B 上执行**，不放在 A | 0644 | 整块按顺序贴到 B 的终端 |
| `profiles/<用户>-<face>.mobileconfig` | 分发给员工 | 0600（目录 0700） | — |

## 部署流程

1. 放好上表里的文件（`bootstrap-ubuntu.sh` 会自动做完这一步）。
2. 通读 `apply.sh` 再执行。它按顺序做：预检查（`routes.sh` / nft 文件 / swanctl 是否存在）→ 逐条 sysctl → 加载 nft → 处理每个 upstream 的二跳单元（`enable` + **`restart`**，等待链路起来）→ `swanctl --load-all` → 调用 `routes.sh`。
3. `systemctl restart strongswan-starter` 之后**必须** `swanctl --load-all`：starter 只负责拉起 charon，不会自己去读 `/etc/swanctl`。漏掉这步机器看着健康、连接数为 0。
4. 跑 `verify.sh`。
5. 按[入站放行](#入站放行)开 A 的入站规则（`apply.sh` 末尾的注释会按你选的 transport 列出该开哪些）。
6. 想让 nft 规则开机持久：交给 A 已有的防火墙机制，或装一个 oneshot 单元。

```ini
# /etc/systemd/system/egressvpn-apply.service
[Unit]
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/egressvpn-apply.sh

[Install]
WantedBy=multi-user.target
```

nftables 规则本身不持久，所以这一步不能省。`egress-b-nft.service`（B 上的 NAT）同理，是 `B-*-peer.txt` 已经装好的 oneshot + `RemainAfterExit=yes`。

**路由为什么不由 `apply.sh` 持有**：指向某块网卡的 IPv4 路由会随该网卡下线/注销被内核剪掉，而且不留任何日志。XFRM 接口被周围一切都牵动 —— 二跳单元重启、strongSwan reload、机房侧链路翻动。真机上 `10.90.1.0/24 dev xvlocal` 消失了几小时，期间客户端照常通过 EAP、forward 规则照样放行、`swanctl -l` 完全健康，但每个回包都被交给默认网关黑洞掉，表现为"连上了，没有网，连内网面板都进不去"。

所以链接、地址、池路由和表 100 的规则全部写在 `routes.sh` 里，`apply.sh` 只是调用它，之后 `egressvpn-routes.timer` 每分钟再调一次。脚本是幂等的事实检查式：每个块只问一个关于**活内核**的问题（`ip -4 route get <池内一个地址>` 会不会走到 `dev xv<face>`），事实没错就一个字都不输出；每次真的动手修补都会写进 `journalctl -u egressvpn-routes.service`，所以"什么时候掉过路由"是查得到的。

不要 `systemctl disable egressvpn-routes.timer`：那等于把这台机器退回"随机全断几小时"的状态。

## 第二跳的两种承载

| | `wireguard`（默认） | `tcp-ssh` |
|---|---|---|
| B 上需要 | `wireguard-tools` + 放行 `udp 51820`（仅对 A 的公网 IP） | 只有 sshd：`PermitTunnel yes`（`B-*-peer.txt` 会写 drop-in） |
| A 上需要放行 | `udp 51820` 入站 | **一条都不需要**，二跳由 A 主动发起走已有 ssh 端口 |
| A 上的产物 | `<接口名>.conf` | runner 脚本 + `.service` + `_ssh_config` |
| 前提 | 两台机器之间 **UDP 双向可达** | TCP 22（或你配的端口）可达 |
| 凭据 | B 的 wg 公钥 + A 的私钥文件 | A 的 ssh 公钥，以受限 `command=` + `from=` 落在 B 的 `authorized_keys` |
| 密钥字段 | `remote-public-key` 必填，`psk-file` 可选 | 写了这两个会报错（ssh 自己加密） |
| 代价 | 需要 UDP 通路 | 单条 TCP 流：A↔B 有 RTT 时链式出口每个请求多付一次往返（实测 ~148 ms），吞吐上限由这条流决定；换回 WireGuard 也一样，这个延迟来自链路而不是承载方式 |

`tcp-ssh` 不是理论选项。真机上实测：从 B 向 A 的 51820/4500/500/443/53 各发 40 个 UDP 包（B 的网卡 TX 计数证明发出去了），A 的网卡抓包**一个都没收到**，同一时刻同源的 TCP SYN 全部到达并被应答。WireGuard 需要双向 UDP，于是它永远握不上手，**且没有任何一条配置检查会报错** —— 接口是 up 的、密钥是对的、`wg show` 只是 `latest-handshakes = 0`、`conntrack` 里留一条 `[UNREPLIED]`，因为丢包发生在 A 的 netfilter 之前。

A 端第一次要生成一对 ssh 密钥（`.pub` 必须存在，渲染时要用它拼 B 的 `authorized_keys`）：

```sh
ssh-keygen -t ed25519 -f /etc/egressvpn/hop2-b_ed25519 -N ''
```

`B-<上游名>-peer.txt` 整块按顺序在 B 上执行即可：它会装 B 端隧道脚本、A 的公钥、`PermitTunnel yes`、转发开关和持久化 NAT 单元。其中 `authorized_keys` 的去重是**按公钥 base64 串**做的 —— sshd 取第一条含该密钥的行，按脚本名过滤会留下上一版渲染的行，于是 B 一直在跑旧的对端脚本，症状是"A 这边链路永远起不来"。

## 客户端描述文件

`out/profiles/<用户>-<face>.mobileconfig` 是给系统设置"添加 VPN 配置描述文件"用的：账号、服务器地址、算法、内嵌 CA 都已填好，员工双击安装，**不需要装任何 App**。

分发方式任选：双击、iCloud/AirDrop、`sudo profiles install -path out/profiles/alice-local.mobileconfig`（需要管理员），或走 MDM 上传文件内容。

每个用户 × 每个 face 一个文件。`alice-local` 和 `bob-via-b` 的区别只有池地址和出口，两者拨的都是 A —— 这是刻意的：员工手上不能出现任何指向 B 的东西，出口切换由 A 上的账号绑定决定。

## 入站放行

`apply.sh` 不生成入站规则，因为那属于 A 上原本就在跑的防火墙。需要手动放行：

- `udp 500`、`udp 4500`、ESP 协议 50 —— 所有客户端
- `transport: wireguard`：`udp <wg-port>`（默认 51820），仅对 A 的公网 IP
- `transport: tcp-ssh`：A 上一跳 2 都不需要放行；B 侧要的是 `PermitTunnel yes`

如果 A 上跑着面板防火墙（宝塔之类），必须在面板自己的界面里加规则 —— 面板重载时会带走你手工塞的规则。这一点在这台机器上是真实的共存关系：面板的规则活在 legacy `ip` 族（`table ip filter`、`ip nat`、ufw 链）里，egressvpn 独占 `table inet egressvpn`，互不覆盖，但**任何一次面板重载都可能改写你的现场**。下结论前先 `nft list ruleset` 看一眼，别假定内核状态和渲染文件一致。

## verify.sh 到底验了什么

自动检查项（全过打印 `all automated checks passed`）：

- swanctl 在位、`eap-mschapv2` 插件在位**并且真的被运行中的 charon 加载**（读 `/proc/<pid>/maps`）
- `egress.nft` 能重新编译；内核里每个池的 forward 规则条数、mssclamp 条数与"只降不升"是否与生成文件一致
- `xv<face>` 设备存在且 up、MTU 是否等于 `tunnel-mtu`、池路由是否在它上面、每设备 `forwarding` 是否开了
- 路由修补器存在且 timer 已 armed
- 二跳链路：`wireguard` 看 `latest-handshakes`，`tcp-ssh` 看 systemd 单元活着并能 ping 通 B 的隧道地址（带 ~15 次重试，见下）
- 策略路由与表 100 生效

两条无法自动化，必须人工确认：

1. relay 用户连上后 `curl ifconfig.me` 返回的是 **B** 的地址，不是 A 的。
2. B 的日志里任何时刻都不出现客户端池地址（`10.90.*`）。

三个已知盲区，读结果时记住：

- 连接加载检查只 grep `users` 里的**第一个**用户名，其他人的 connection 没加载也会 PASS。多 face 时自己 `swanctl -l` 看一遍。
- `tcp-ssh` 的 ping 检查紧跟 `apply.sh` 会短暂 FAIL：B 那端是 forced ssh command，要等重连后才配置设备。**不是链路坏了**，生成的 verify 已经带 15 秒重试。
- 没有 `wg show` 检查用于 `tcp-ssh`：隧道设备不是 WireGuard，一条只能在工作正常的部署上报失败的检查比没有检查更糟。

## 日常运维

**改口令**：覆盖 `password-ref` 指向的文件 → 重跑 `render` → 新的 `egressvpn.conf` 放到 `/etc/swanctl/conf.d/` → `sudo swanctl --load-all`。**加用户**同理，再发一个新的 `.mobileconfig`。

**删用户**也是同样流程，而且真的生效：`--load-all` 会卸载已经不在文件里的 connection（实测输出 `successfully loaded 1 connections, 1 unloaded`）。别去调 `swanctl --flush`，5.9 只有 `--flush-certs`。要立刻断已经在跑的隧道：`sudo swanctl --terminate --ike-id <IKE_ID>`；不干预的话最迟下一次 `reauth_time` 重认证被拒。

**看谁在连接**：`sudo swanctl -l`。空输出是"没人连"，不是"服务坏了"。

**重渲染后完整生效的顺序**：放文件 → `swanctl --load-all`（只热加载 SA）→ 改到 `charon` 段的任何键（包括 `install_routes`、插件 `load`）都要 `systemctl restart strongswan-starter` + 再 `--load-all` → 防火墙变了就 `nft -f /etc/nftables.d/egress.nft` → 路由立刻对一遍：`systemctl restart egressvpn-routes.timer` 或直接 `sudo sh /usr/local/sbin/egressvpn-routes.sh`。

oneshot 单元要 `restart` 而不是 `start`：`start` 一个已 active 的 oneshot 是空操作，会导致"文件已经换了、内核里还是旧规则"。同理，`ip rule` **没有** `replace` 子命令（只有 add/delete/change/get），幂等写法是先 `ip rule del priority N 2>/dev/null || true` 再 add。

**备份**：`/etc/egressvpn/`（配置表 + 口令文件 + 二跳私钥）、`/etc/swanctl/`（证书与私钥）、`/etc/egressvpn/ca/`（内部 CA 的私钥，丢了所有人的客户端都要重发）。

**升级本工具**：换 `/usr/local/bin/egressvpn` → 重跑 `validate` + `render` → diff `out/` 和线上文件 → 按上面的顺序放置并加载。渲染结果的可读注释只在文件里，线上文件被谁手改过一眼就能看出来。

## 故障速查

先定症状，再看日志；日志只有 `journalctl -u strongswan-starter` 一处。

| 症状 | 一条命令 | 结论 |
|---|---|---|
| 连上秒断 | `journalctl -u strongswan-starter --since -5min \| grep 'no matching'` | peer config 没匹配上，多半是 `remote.id` 被钉死了（生成为 `%any`，别改） |
| IKE 通、IKE_AUTH 失败 | `grep eap-mschapv2 /proc/$(pgrep -x charon)/maps` | 没输出 = 插件没被**加载**（不是没装）。检查 `/etc/strongswan.d/egressvpn.conf` 里 `load = yes`，然后重启 charon |
| 一个 face 全断、另一个正常，连 A 的内网面板都打不开 | `ip -4 route get <池内一个地址>` | 结果不是 `dev xv<face>` 就是池路由被内核剪了。timer 一分钟内自愈；查 `journalctl -u egressvpn-routes.service` |
| 已连接、没有网络 | `conntrack -L \| grep 10.90.` | 全 `[UNREPLIED]` = 出去了没回来；一条都没有 = 包没进 FORWARD。再看 `ip xfrm policy`，出现通配 `dir out` 就是没走 XFRM 接口 |
| 面板能开、公网没网 | `nft list chain inet egressvpn forward` | 条数和 `verify.sh` 报的不符 = 链顶有人工插的 `drop` 探针。`nft -f /etc/nftables.d/egress.nft` 恢复 |
| 能上网但很慢 | 客户端 `ifconfig ipsec0 \| grep mtu` + `ping -c 20 -D -s 1264 1.1.1.1` | 大包 100% 丢 = MTU/钳制问题。`nft list chain inet egressvpn mssclamp` 的钳制值必须 ≤ 隧道 MTU − 40 **且带范围匹配** |
| 整个 A 上不了网 | `ip route show default` | charon 装了 0/0 进隧道的默认路由 → `install_routes = no` 丢了 |
| via-b 出去还是 A 的 IP | `ip rule show \| grep 'lookup 100'`；`ip -br link show wgb` | 策略路由或第二跳链路没起来。`tcp-ssh` 下先看 `systemctl status egressvpn-hop2-b` |
| 二跳永远没有 handshake | B 上 `ping -c2 A的IP`，A 上 `tcpdump -ni <网卡> udp port 51820 -c 3` | UDP 单向被丢（本项目实测现象）。改 `transport: tcp-ssh` |
| 客户端显示已连接但一条 VPN 路由都不加 | `swanctl -l` 看 TS | 两端不是 `0.0.0.0/0`，即 `local_ts/remote_ts` 没显式写（默认 `dynamic`） |

**"已连接但没有网络"不看日志，看计数器**：charon 只记 IKE，数据面的包一个都不记，`journalctl` 里再怎么说 `installed CHILD_SA` 也证明不了有人在转发。三条判据（都在真机上用过）：

```sh
# 1. 客户端的包到底有没有被转发出去 / 有没有回音进来。counter 规则要 insert 到
#    accept/drop 之前，追加到终态规则后面等于没加。
nft insert rule inet egressvpn forward ip saddr 10.90.1.0/24 counter comment probe_out
nft insert rule inet egressvpn forward ip daddr 10.90.1.0/24 counter comment probe_back
# 2. 全 [UNREPLIED] = 包出去了但没有回来；out/back 都是 0 = 包根本没进 FORWARD
conntrack -L | grep 10.90.
# 3. SA 是不是真的绑到了 xfrm 设备（没绑就是通配策略）
ip xfrm policy | grep -E 'src|dir|if_id'
```

用完**必须**清掉探针，而可靠的做法不是按 comment 找 handle 删（真机上就这么漏删过一条 tab 缩进的规则，之后表现为"面板能开、公网没网"，隧道 healthy、日志零错误），而是直接重来一遍：`nft -f /etc/nftables.d/egress.nft`，它先 flush 再按文件重建。另一个便宜的旁证是**服务器自己还能不能上网** —— A 自己断网而客户端显示已连接，基本就是通配 `dir out` 策略把 A 的流量也加密回隧道了。

**"能上网但很慢"先量隧道口，别猜 CPU**：真机上 2 vCPU 跑满时几乎全 idle、AES-NI 也在，瓶颈却是 MTU。

```sh
ifconfig ipsec0 | grep mtu                                  # macOS 的 IKEv2 口自己就是 1280
for p in 1252 1264; do ping -c 20 -D -s $p 1.1.1.1; done    # -D 不分片，-s 定载荷
```

`payload=1252` 全通、`payload=1264`（inner 1292）全丢，就是路径 MTU 被卡死，跟加密、跟带宽都无关。对照 A 上的两件事：`ip -d link show xv<face>` 的 mtu，和 mssclamp 里的钳制值（后者必须 ≤ 前者 − 40 且带范围匹配）。`verify.sh` 已经把这几条做成自动检查，FAIL 的修法都是重跑 `nft -f ...` 或 `apply.sh`，不要手改内核。

顺带排掉两个假嫌疑人：A 是**转发**角色，`net.core.rmem_max` / `net.ipv4.tcp_rmem` 调的是 A 自己的 socket，对穿过隧道的流量不起作用；`esp-proposals` 从 CBC+HMAC 换成 GCM 只省 CPU，而 CPU 本来就没占用，且换 GCM 会让描述文件生成失败（见 `tuning`），别当性能手段用。

**DNS 与转发要分开判断**：`dig @1.1.1.1` 超时而 `ping 1.1.1.1` 正常，先怀疑有没有隧道里那条路由，不要先怀疑 DNS。真机上出现过"域名打不开、IP 字面量能开"，最后原因是链顶一条人工 `drop` 探针。

## 真机上校对过的细节

以下几条（含上面若干节里的措辞）都是拿真机（Ubuntu 24.04 / strongSwan 5.9.13 / nft 1.0.9 / kernel 6.8）校对过的，改动前请留意：

- **`ip rule` 没有 `replace` 子命令**（只有 add / delete / change / get，`ip route` 才有 replace）。`apply.sh` 是 `set -e` 的，写错这一步会当场停在 nft 加载和 `swanctl --load-all` 之前，机器看着"部署过了"其实是半套。
- `/etc/wireguard/<接口名>.conf` 是 **`wg setconf` 的文件，不是 wg-quick 的文件**：`Address`、`MTU` 这两个键 `wg setconf` 不认，会直接 `Line unrecognized: Address=10.91.0.2/32` 把 `apply.sh` 打断；地址和 MTU 由 `apply.sh` 用 `ip -4 address replace` / `ip link set mtu` 来做。故意不给 `wg-quick` 用：peer 里的 `AllowedIPs = 0.0.0.0/0` 交给 wg-quick 会变成 A 自己的默认路由，把主机流量整条拽进链路。B 那一侧反过来 —— 它用 wg-quick，所以 `[Interface]` 里要写 `Address`，而 `PrivateKeyFile` 在 wg-quick 里同样不认（它也把未知键转给 `wg setconf`），必须写 inline 的 `PrivateKey`。
- nft 的 MSS 选项叫 `maxseg`、可写的成员叫 `size`，`tcp option mss clamp value` 直接编译不过。**钳制必须写成"只降不升"**：`tcp option maxseg size <值+1>-65535 tcp option maxseg size set <值>`。不带范围匹配的 `size set N` 是**无条件改写**，客户端本来只敢 advertise 1240，它会把 1340 塞回去，对端于是发 1380 的包，客户端隧道口（macOS 实测 1280）整个丢掉 —— 症状是"能连、能上网、就是很慢"，ping 得通而大流量全军覆没（payload 1280 丢 0%，1292 丢 100%）。两个方向都要钳：客户端的 SYN 决定对端能发多大的下载段，对端的 SYN-ACK 决定客户端能发多大的上传段，只钳前者遇到 MTU 更大的 Windows 客户端就会漏。
- connection 里是 `reauth_time`，没有 `reauth` 这个键；`local<1>`/`remote<1>` 合法，但 `children<1>` 非法（`children` 是带名字的字典）。写错一个键 strongSwan 不会忽略，而是整段 config 丢弃、一条 connection 都加载不了。
- **全隧道要显式写 `local_ts = 0.0.0.0/0` 和 `remote_ts = 0.0.0.0/0`**，省掉它们不是全隧道。两者的默认值是 `dynamic`，strongSwan 会替换成隧道外层地址和客户端的虚拟 IP：真机上协商出来的是 `10.0.1.2/32 === 10.90.1.1/32`，客户端显示"已连接"、路由表却一条 VPN 路由都不加，流量全走本机网络。判断方法：`swanctl -l` 看 TS，两端都该是 `0.0.0.0/0`。
- **但只有 0/0 还不够，转发型服务器必须用 XFRM 接口（`if_id_in`/`if_id_out`）**。这一条是"连上了但没网络"的真正原因：策略式 IPsec 在 `remote_ts = 0.0.0.0/0` 时会在主策略库里插一条通配的 `src 0.0.0.0/0 dst 0.0.0.0/0 dir out`，凡是这台机器转发的包 —— 包括客户端已经 masquerade 过的包，也包括 A 自己的包 —— 都命中它、被重新加密塞回同一条隧道。实测现象完全对得上：客户端包能到 FORWARD 并被 SNAT，`conntrack -L` 里池地址全是 `[UNREPLIED]`，同时 A 自己访问公网也一起挂掉。
  解法是给每个 face 建一个 XFRM 接口（`ip link add name xv<face> type xfrm dev <inbound-interface> if_id N`），child 里写对应的 `if_id_in`/`if_id_out`，SA 和策略就绑到这个设备上，"什么流量进隧道"重新由路由决定；`routes.sh` 再补 `ip route replace <pool> dev xv<face>`。三个配套坑：`charon.install_routes` 必须关掉（否则 0/0 会变成一条走 xfrm 设备的默认路由）、`net.ipv4.conf.xv<face>.forwarding = 1` 必须按接口打开（解密后的包 iif 就是这个设备，只开 `conf.all` 不够）、内核要 ≥ 4.19 且有 `xfrm_interface` 模块。`xfrm` 设备的 MTU 用 `tuning.tunnel-mtu`（默认 1280，macOS 自己就是这么定的），它和 `tuning.mss-clamp`（默认 `tunnel-mtu - 40`，`Validate()` 拒绝更大的值）是同一件事的两半：设备决定隧道里塞得下多大的包，钳制决定对端别发那么大的包。`tuning.mtu` 只管第二跳链路（两种 transport 都归它），和隧道口无关。
- `/etc/strongswan.d/egressvpn.conf` 是**一份合并好的覆盖文件**，插件 `load = yes` 和 `install_routes = no` 都在里面。这个文件是顶层 include，谁"只改一个键"而整份重写它，重启后 charon 就没有 eap-mschapv2 了，日志里是 `loading EAP_MSCHAPV2 method failed`、客户端一律 `EAP/FAIL`（真机上踩过，表现是"VPN 都连不上了"）。确认插件到底加载没有，只看 `/proc/$(pgrep -x charon)/maps` 里有没有 `libstrongswan-eap-mschapv2.so`（插件名里的连字符在文件名里也是连字符）。
- 客户端的 IKE ID **不参与匹配**（生成的是 `id = %any`）。macOS/iOS 在没有 Local Identifier 时拿本机 IP 当 IDi（实测是 `172.20.10.53` 这种热点地址），把 `remote.id` 钉成用户名会在检查口令之前就先 `no matching peer config found` 拒掉，表现就是"连上秒断"。真正认证的是 EAP 用户名。
- **`ip route show exact 10.90.1.0/24 dev xvlocal` 在这台机器上打印匹配项时不会重复 `dev` 字段**（输出是 `10.90.1.0/24 scope link`），所以任何 grep 设备名的事实检查会永远失败、每分钟重建一个健康的 face。`routes.sh` 用的是 `ip -4 route get <池内地址>`，那才是真正决定 face 能不能用的问题。
- `apt install` 不会重建被删掉的 `/etc/strongswan.d/charon/*.conf`（它们是 conffile，装过就不会再写）。如果 charon 起不来、报 `unmet dependency: NONCE_GEN` 之类的缺插件错误，先 `dpkg -V libstrongswan` 看有没有一堆 `missing`，再用下面这条补齐：

```sh
sudo apt-get install -y --reinstall -o Dpkg::Options::=--force-confmiss \
     libstrongswan libstrongswan-standard-plugins libstrongswan-extra-plugins \
     strongswan-libcharon strongswan-charon strongswan-starter strongswan-swanctl
```

- **不要往 charon 配置里加 `filelog` 段**：一旦定义了任何 `filelog`，charon 就不再创建默认的 stderr 日志，而 Ubuntu 自带的 AppArmor profile（`/etc/apparmor.d/usr.lib.ipsec.charon`）没给 `/usr/lib/ipsec/charon` 写 `/var/log` 的权限，文件创建不了，于是"日志一个字都没有的 VPN 故障"。真需要独立文件就同时改 `/etc/apparmor.d/local/usr.lib.ipsec.charon`。
- `swanctl -l` 空输出是没人连，不是服务坏了。`ping <池 VIP>`（例如 `10.90.1.1`）从客户端发起 100% 丢包且毫无意义 —— 那个 VIP 是客户端**自己**的隧道地址，没人应答它；量隧道要用 `ping -D -c 20 -i 0.5 1.1.1.1` 并在跑着负载的时候测。

调试 peer 匹配时开临时日志级别，看完删掉：

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

## 实测数据

一台 2 vCPU / 1 公网 IP 的 A，Ubuntu 24.04 + strongSwan 5.9.13，客户端是 macOS（内置 IKEv2，走手机热点 NAT）：

| 指标 | 修 MTU 前 | 修 MTU 后 |
|---|---|---|
| 单流下载 | ~353 KB/s，ICMP 丢 25% | 0.7–3.0 MB/s |
| 4 并行流合计 | 未测 | ~3.5 MB/s，丢包 0% |
| 隧道内 `ping 1.1.1.1`（负载中） | — | 26 ms 平均，0% 丢包 |
| 参照：在 A 本机 curl 同一端点 | — | 2.3 MB/s 单流 |

- 路径 MTU：载荷 1252 全通、1264（inner 1292）100% 丢 —— `ipsec0` 就是 1280。
- A↔B 隧道 RTT ~150 ms，链式出口每个请求多付一次这个往返，与承载方式无关。
- A 上解析器延迟（各 5 次）：8.8.8.8 ~135 ms、1.1.1.1 ~151 ms、119.29.29.29 ~266 ms、223.5.5.5 ~2207 ms —— 所以下发 `1.1.1.1` 作为首选是对的。
- 路由修补器实测：手删 `10.90.1.0/24 dev xvlocal` 后 85 秒内被 timer 重建；内核状态正常时整分钟零输出。

这些数字是单机房、单客户端的观测，不是基准测试。剩余波动来自热点的 per-flow 整形和 CDN 边缘选择，而不是隧道。

## 设计决策

- **为什么是 IKEv2 + EAP-MSCHAPv2**：客户端是公司 Mac，装 App 不在默认许可范围内，于是系统内置协议是唯一现实路径。L2TP/Cisco IPsec 被否（全员共享 PSK、吞吐更差）；WireGuard 更快但要 App Store 或 Homebrew `wireguard-tools`。**如果实际上允许装客户端**，EAP-TLS（每人一张证书）明显优于 EAP-MSCHAPv2，值得重做第一跳。
- **为什么二跳默认 WireGuard**：两端都是 Linux，没有"客户端不能装东西"的限制，同时避开 IPsec-in-IPsec 的 XFRM 复杂度。UDP 单向被丢时换 `tcp-ssh`，设备名/路由/nft 全不变。
- **为什么 `apply.sh` 由工具生成但不由工具执行**：它改的是活主机上的路由和防火墙。二进制只渲染；先读再跑。
- **为什么自己写 YAML 解析器（`internal/yamlite`）**：构建环境拉不到 `proxy.golang.org`，所以整个项目零外部依赖。要换完整 YAML 只需改 `internal/config/config.go` 的 `Load` 和 struct tag。
- **为什么 face 用地址池而不是 mark 区分**：池是内核里唯一不需要额外状态就能同时被 nft、策略路由和 XFRM 设备一致识别的标识；mark 需要在两条链上保持同步，出错时的表现是"某个 face 静默走错出口"。
- **为什么 Go 不实现任何 crypto/IKE**：加密实现的风险不该由一个渲染器承担。

## 安全模型与已知边界

**凭据**：

- 每个用户的明文口令存在 A 上（`egressvpn.conf`，0600）—— EAP-MSCHAPv2 的工作方式决定了服务器必须能看到口令。它是弱凭据：口令过线校验，MSCHAPv2 本身也已被证明对抗中间人有缺陷。
- `B` 的凭据（wg 私钥 / ssh 私钥）只存在于 A 的一个 0600 文件里，不进渲染结果、不进描述文件。
- `embed-password: true` 之后描述文件本身等于凭据，不要经邮件/网盘/工单系统分发。
- **强烈建议**：SSH 不要用密码登录（改 `PasswordAuthentication no` + 密钥），并把 `sshd`、面板、本工具的管理入口分成不同凭据。任何出现在聊天记录/工单里的口令都应视为已泄露并轮换。

**已知边界**（都是有意取舍，不是 bug）：

- **YAML 是受限子集**，见[配置参考](#配置参考)。
- **每个用户一段 connection**，几百个账号会让 `egressvpn.conf` 膨胀、加载变慢；规模上去后要换 RADIUS + 按 group 匹配，那是另一次改造。
- **IPv6 会泄漏**：客户端会请求 `%any6` 但拿不到 v6 地址，v6 流量继续走它本地网络。要么客户端侧禁用 v6，要么再加一套 v6 SA/池。
- **macOS 会在空闲约 80–90 秒后拆掉隧道**（没有持续流的时候），重连由系统按需发起；这不是服务端配置能改的行为。
- **杀开关只在 face 层**：relay face 依赖表 100 的唯一默认路由，二跳链路断时客户端会黑屏而不是回落 A 的 IP（这是要的行为），但没有 per-app 策略。
- **不做流量伪装 / DPI 规避**，且这类需求应当先走合规审批。
- 单 A 单点：A 挂了所有人的出口都断。高可用要自己解决（浮动 IP / 多 A + DNS），本工具不含。

## 代码结构

```
cmd/egressvpn/main.go          CLI：validate / render / genkey / genpsk / version，退出码约定
internal/config/config.go      配置 struct、默认值、Validate() 的全部规则、ResolvePassword()
internal/yamlite/              受限 YAML 子集解析器（零依赖的代价所在）
internal/render/render.go      全部产物：swanctl conf.d、charon 覆盖、egress.nft、sysctl、
                               routes.sh + .service/.timer、apply.sh、二跳单元、B 的 peer 块
internal/render/verify.go          自动检查项（见上文的三个盲区）
internal/render/mobileconfig.go .mobileconfig 生成（含算法串的解析）
internal/wgkey/key.go          genkey/genpsk
example/egress.yaml            完整可用的示例表（文档保留 IP，可直接抄）
scripts/bootstrap-ubuntu.sh    一条龙装到"等你跑 apply.sh"为止
build.sh                       交叉编译 + 打包（先 build + test，任一失败即停）
```

`internal/render` 的输出是有测试断言的：生成的脚本里每一条关键命令（`PermitTunnel yes`、按公钥去重 `authorized_keys`、`systemctl restart` 而不是 `start`、mssclamp 的范围匹配、timer 的 `After=` 依赖）都有对应测试，改渲染逻辑时先看测试怎么写的。

## 开发与贡献

```sh
go build ./... && go test ./...     # 无外部依赖，离线可跑
gofmt -l .
bash build.sh VERSION=x.y.z         # 在 macOS 上建议 bash build.sh（可执行位容易丢）
```

改配置项请同步三处：`internal/config`（解析 + 校验 + 默认值）、`internal/render`（用法）、`example/egress.yaml`（文档）。生成的 shell/nft 属于"给活主机看的产物"，请在测试里断言它的形状而不是靠肉眼验收 —— 本仓库里几个最贵的 bug 都是"检查在正常部署上必然 FAIL"或"必然空过"那一种。

提 issue 时请给出：症状 + `swanctl -l` 输出 + `ip -4 route get <池内地址>` + `nft list chain inet egressvpn forward` 的条数。版本信息 `egressvpn version`。

## 许可与免责

MIT，见 [`LICENSE`](LICENSE)。

本工具会修改主机的路由和防火墙。请在测试机上完整走一遍 `TUTORIAL.md` 并在变更窗口内生产部署；`apply.sh` 必须先读再跑。使用者需自行确认部署行为符合所在组织的安全与合规要求 —— 本项目不提供任何流量伪装能力，也不为此类用途做设计。
