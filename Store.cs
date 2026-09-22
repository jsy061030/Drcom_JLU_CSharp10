using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;

namespace DrcomClient;

/// <summary>
/// 读取 Rust/WebUI 写出的 <c>~/.drcomconfig</c> 配置文件。
/// </summary>
/// <remarks>
/// 该文件为 JSON，所有字段可选；密码用 MAC（去掉 <c>:</c>/<c>-</c>）作为 key 逐字节 XOR 后保存为 16 进制。
/// </remarks>
public static class DrcomConfigStore
{
    /// <summary><c>~/.drcomconfig</c> 的完整路径。</summary>
    public static string ConfigPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        ".drcomconfig");

    /// <summary>
    /// 尝试加载 <c>~/.drcomconfig</c>；文件不存在时返回 <c>null</c>。
    /// </summary>
    /// <exception cref="IOException">文件存在但格式非法时抛出。</exception>
    public static Config? TryLoad()
    {
        string path = ConfigPath;
        if (!File.Exists(path))
        {
            return null;
        }

        string text = File.ReadAllText(path, Encoding.UTF8);
        var plain = JsonSerializer.Deserialize<PlainConfig>(text, JsonOptions)
            ?? throw new IOException($"invalid config file: {path}");

        var config = new Config();
        Apply(config, plain);
        config.Validate();
        return config;
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    private static void Apply(Config config, PlainConfig plain)
    {
        if (plain.server is not null) config.Server = plain.server;
        if (plain.username is not null) config.Username = plain.username;
        if (plain.host_ip is not null) config.HostIp = plain.host_ip;
        if (plain.mac is not null) config.Mac = plain.mac;
        if (plain.host_name is not null) config.HostName = plain.host_name;
        if (plain.primary_dns is not null) config.PrimaryDns = plain.primary_dns;
        if (plain.dhcp_server is not null) config.DhcpServer = plain.dhcp_server;
        if (plain.bind_ip is not null) config.BindIp = plain.bind_ip;
        if (plain.control_check_status is not null) config.ControlCheckStatus = plain.control_check_status;
        if (plain.adapter_num is not null) config.AdapterNum = plain.adapter_num;
        if (plain.ip_dog is not null) config.IpDog = plain.ip_dog;
        if (plain.auth_version is not null) config.AuthVersion = plain.auth_version;
        if (plain.keep_alive_version is not null) config.KeepAliveVersion = plain.keep_alive_version;
        if (plain.is_test is not null) config.IsTest = plain.is_test.Value;
        if (plain.unlimited_retry is not null) config.UnlimitedRetry = plain.unlimited_retry.Value;

        if (plain.password is not null)
        {
            string key = KeyFromMac(plain.mac);
            config.Password = DecryptXorHex(plain.password, key);
        }
    }

    private static string KeyFromMac(string? mac)
    {
        if (string.IsNullOrEmpty(mac))
        {
            throw new IOException("mac is required to decrypt password");
        }

        string key = mac.Replace(":", "").Replace("-", "").Trim();
        if (key.Length == 0)
        {
            throw new IOException("mac is empty");
        }

        return key;
    }

    private static string DecryptXorHex(string hex, string key)
    {
        if (hex.Length % 2 != 0)
        {
            throw new IOException("odd hex length in encrypted password");
        }

        byte[] keyBytes = Encoding.UTF8.GetBytes(key);
        var bytes = new byte[hex.Length / 2];

        for (int i = 0; i < hex.Length; i += 2)
        {
            byte b = byte.Parse(hex.AsSpan(i, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            bytes[i / 2] = (byte)(b ^ keyBytes[(i / 2) % keyBytes.Length]);
        }

        return Encoding.UTF8.GetString(bytes);
    }

    private sealed class PlainConfig
    {
        public string? server { get; set; }
        public string? username { get; set; }
        public string? password { get; set; }
        public string? host_ip { get; set; }
        public string? mac { get; set; }
        public string? host_name { get; set; }
        public string? primary_dns { get; set; }
        public string? dhcp_server { get; set; }
        public string? bind_ip { get; set; }
        public string? control_check_status { get; set; }
        public string? adapter_num { get; set; }
        public string? ip_dog { get; set; }
        public string? auth_version { get; set; }
        public string? keep_alive_version { get; set; }
        public bool? is_test { get; set; }
        public bool? unlimited_retry { get; set; }
    }
}
