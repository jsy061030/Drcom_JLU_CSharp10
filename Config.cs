using System.Globalization;
using System.Text;

namespace DrcomClient;

/// <summary>
/// Dr.COM 客户端配置。
/// </summary>
/// <remarks>
/// 认证信息（Server / Username / Password / HostIp / Mac）必须提供；
/// 其余协议字段使用与原版脚本一致的默认值。
///
/// 配置文件为扁平的 <c>key = value</c> 形式（类 TOML），支持 <c>#</c> 注释与引号。
/// </remarks>
public sealed class Config
{
    public string Server { get; set; } = "";
    public string Username { get; set; } = "";
    public string Password { get; set; } = "";
    public string HostIp { get; set; } = "";
    public string Mac { get; set; } = "";
    public string HostName { get; set; } = "YOURPCNAME";
    public string PrimaryDns { get; set; } = "10.10.10.10";
    public string DhcpServer { get; set; } = "0.0.0.0";
    public string BindIp { get; set; } = "0.0.0.0";

    // 协议固定字段，使用十六进制字符串表示
    public string ControlCheckStatus { get; set; } = "20";
    public string AdapterNum { get; set; } = "03";
    public string IpDog { get; set; } = "01";
    public string AuthVersion { get; set; } = "68 00";
    public string KeepAliveVersion { get; set; } = "dc 02";

    public bool IsTest { get; set; } = true;
    public bool UnlimitedRetry { get; set; } = true;

    /// <summary>从配置文件加载。</summary>
    /// <exception cref="IOException">文件不存在或格式非法时抛出。</exception>
    public static Config FromFile(string path)
    {
        if (!File.Exists(path))
        {
            throw new FileNotFoundException($"config file not found: {path}", path);
        }

        var config = new Config();
        var lines = File.ReadAllLines(path, Encoding.UTF8);
        for (int i = 0; i < lines.Length; i++)
        {
            string line = lines[i].Trim();
            if (line.Length == 0 || line.StartsWith('#'))
            {
                continue;
            }

            int eq = line.IndexOf('=');
            if (eq < 0)
            {
                throw new IOException($"invalid config line {i + 1}: {line}");
            }

            string key = line[..eq].Trim();
            string value = Unquote(line[(eq + 1)..].Trim());
            config.Set(key, value, i + 1);
        }

        config.Validate();
        return config;
    }

    private void Set(string key, string value, int lineNo)
    {
        switch (key.ToLowerInvariant())
        {
            case "server": Server = value; break;
            case "username": Username = value; break;
            case "password": Password = value; break;
            case "host_ip": HostIp = value; break;
            case "mac": Mac = value; break;
            case "host_name": HostName = value; break;
            case "primary_dns": PrimaryDns = value; break;
            case "dhcp_server": DhcpServer = value; break;
            case "bind_ip": BindIp = value; break;
            case "control_check_status": ControlCheckStatus = value; break;
            case "adapter_num": AdapterNum = value; break;
            case "ip_dog": IpDog = value; break;
            case "auth_version": AuthVersion = value; break;
            case "keep_alive_version": KeepAliveVersion = value; break;
            case "is_test": IsTest = ParseBool(value, lineNo); break;
            case "unlimited_retry": UnlimitedRetry = ParseBool(value, lineNo); break;
            default:
                throw new IOException($"unknown config key on line {lineNo}: {key}");
        }
    }

    private static bool ParseBool(string value, int lineNo) => value.ToLowerInvariant() switch
    {
        "true" or "1" or "yes" => true,
        "false" or "0" or "no" => false,
        _ => throw new IOException($"invalid boolean on line {lineNo}: {value}"),
    };

    private static string Unquote(string value)
    {
        if (value.Length >= 2 &&
            ((value[0] == '"' && value[^1] == '"') || (value[0] == '\'' && value[^1] == '\'')))
        {
            return value[1..^1];
        }
        return value;
    }

    internal void Validate()
    {
        if (Server.Length == 0) throw new IOException("config: 'server' is required");
        if (Username.Length == 0) throw new IOException("config: 'username' is required");
        if (Password.Length == 0) throw new IOException("config: 'password' is required");
        if (HostIp.Length == 0) throw new IOException("config: 'host_ip' is required");
        if (Mac.Length == 0) throw new IOException("config: 'mac' is required");
    }

    /// <summary>将 MAC 字符串解析为 48 位无符号整数。</summary>
    /// <remarks>支持 <c>AA:BB:CC:DD:EE:FF</c>、<c>AA-BB-CC-DD-EE-FF</c> 或 <c>AABBCCDDEEFF</c>。</remarks>
    public ulong ParseMac()
    {
        string s = Mac.Replace(":", "").Replace("-", "").Trim();
        if (!ulong.TryParse(s, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out ulong mac))
        {
            throw new IOException($"invalid MAC address: {Mac}");
        }
        return mac;
    }

    /// <summary>将 IPv4 点分字符串解析为 4 字节数组。</summary>
    public static byte[] ParseIp(string ip)
    {
        string[] parts = ip.Split('.');
        if (parts.Length != 4)
        {
            throw new IOException($"invalid IPv4: {ip}");
        }
        var bytes = new byte[4];
        for (int i = 0; i < 4; i++)
        {
            if (!byte.TryParse(parts[i], NumberStyles.None, CultureInfo.InvariantCulture, out bytes[i]))
            {
                throw new IOException($"invalid IPv4: {ip}");
            }
        }
        return bytes;
    }

    /// <summary>将十六进制字符串（可含空格）解析为字节数组。</summary>
    public static byte[] ParseHex(string hex)
    {
        var sb = new StringBuilder(hex.Length);
        foreach (char c in hex)
        {
            if (!char.IsWhiteSpace(c))
            {
                sb.Append(c);
            }
        }

        string compact = sb.ToString();
        if (compact.Length % 2 != 0)
        {
            throw new IOException($"odd hex length: {hex}");
        }

        var result = new byte[compact.Length / 2];
        for (int i = 0; i < result.Length; i++)
        {
            if (!byte.TryParse(compact.AsSpan(i * 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out result[i]))
            {
                throw new IOException($"invalid hex: {hex}");
            }
        }
        return result;
    }
}
