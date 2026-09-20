# DrcomClient（C#）

Dr.COM 校园网认证客户端的 C# 实现，跨平台（Windows / Linux / macOS），
基于 .NET 10，**无第三方依赖**（仅用 BCL）。

## 功能

- Challenge 认证（获取 salt）
- 登录认证（构造完整登录报文）
- 持续保活（keep_alive1 + keep_alive2）
- 交互式注销（按 `q` → 按 `y`）
- 配置文件查找：可执行文件所在目录下的 `drcom.toml`
- 详细报文日志（`is_test = true` 时）

## 项目结构

| 文件 | 说明 |
|------|------|
| `Program.cs` | 命令行入口、配置路径解析 |
| `Config.cs` | 配置模型与解析（扁平 `key = value`） |
| `Protocol.cs` | 协议底层：MD5、dump、ror、checksum、登录/保活/注销报文 |
| `Client.cs` | UDP socket、Challenge/Login/KeepAlive 流程、注销 |

> 核心逻辑（`Config` / `Protocol` / `Client`）与入口解耦，可被其他 C# 项目引用复用。

## 构建

需要 .NET SDK（本机位于 `C:\Users\17408\.dotnet`，未加入 PATH）：

```cmd
"%USERPROFILE%\.dotnet\dotnet.exe" build -c Release
```

产物：`bin\Release\net10.0\drcom-client.exe`

## 使用

1. 复制示例配置并填写：

```cmd
copy drcom.toml.example drcom.toml
```

```toml
server = "10.100.61.3"
username = "your_username"
password = "your_password"
host_ip = "192.168.1.2"
mac = "AA:BB:CC:DD:EE:FF"
```

2. 运行：

```cmd
:: 使用可执行文件所在目录下的 drcom.toml
bin\Release\net10.0\drcom-client.exe

:: 指定配置文件路径
bin\Release\net10.0\drcom-client.exe D:\path\to\drcom.toml
```

### 注销会话

程序运行（保活）期间，在终端中：

- 按 `q` → 询问「是否注销？(y/n)」
- 按 `y` → 发送注销报文并退出
- 按其他键 → 取消注销，继续保活

## 配置字段

### 必填

| 字段 | 说明 |
|------|------|
| `server` | 认证服务器 IP |
| `username` | 用户名 |
| `password` | 密码 |
| `host_ip` | 本机 IP |
| `mac` | 本机 MAC（`AA:BB:CC:DD:EE:FF` 或 `AABBCCDDEEFF`） |

### 可选（含默认值）

| 字段 | 默认值 |
|------|--------|
| `host_name` | `YOURPCNAME` |
| `primary_dns` | `10.10.10.10` |
| `dhcp_server` | `0.0.0.0` |
| `bind_ip` | `0.0.0.0` |
| `control_check_status` | `20` |
| `adapter_num` | `03` |
| `ip_dog` | `01` |
| `auth_version` | `68 00` |
| `keep_alive_version` | `dc 02` |
| `is_test` | `true` |
| `unlimited_retry` | `true` |

## 与其他实现的关系

本实现与原 Python 脚本、Rust 版本（`../drcom-client`）逻辑一致：

- 报文构造、MD5、密码混淆（`ror`）、校验和算法均按原脚本逐字段对应。
- 配置使用同一套字段名。
- 注销报文（命令字 `0x06`）为原脚本所无，依据通用 Dr.COM 实现推导，
  若服务器不接受请对照抓包调整 `Protocol.Logout`。

### 校验和的"正则怪癖"已刻意保留

原脚本的 `checksum()` 用 `re.findall(b'....', s)` 分块，而 Python 正则中的 `.`
**默认不匹配换行字节 `0x0A`**。由于 `primary_dns = 10.10.10.10` 会产生 `0a 0a 0a 0a`，
扫描会右移重新对齐，结果与"固定 4 字节分组"**不同**。本实现（`Protocol.Checksum`）
**故意复刻**该行为以保证报文逐字节一致。

### 报文一致性

`Md5Sum`、`Dump`、`Checksum`、`Mkpkt`、`KeepAlivePackageBuilder` 的输出已与原 Python
脚本逐字节比对通过（相同输入 → 完全相同的报文）。

## 注意事项

1. **UDP 端口 61440**：客户端绑定本地 61440，确保未被占用。
2. **明文密码**：配置文件中为明文，请妥善保管，勿提交到版本库。
3. **`q`/`y` 交互**：需要交互式控制台；输入被重定向时键盘监听自动跳过，
   此时可通过 `Client.RequestStop()` 从代码中停止。
