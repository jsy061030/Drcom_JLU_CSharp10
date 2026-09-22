using DrcomClient;

// Dr.COM 客户端命令行入口。
//
// 配置文件查找顺序：
//   1. 命令行第一个参数指定的路径；
//   2. 可执行文件所在目录下的 drcom.toml；
//   3. 用户主目录下的 ~/.drcomconfig（Rust/WebUI 写出的 JSON 格式）。

const string SampleConfig = """
server = "10.100.61.3"
username = "your_username"
password = "your_password"
host_ip = "192.168.1.2"
mac = "AA:BB:CC:DD:EE:FF"

# 以下为可选项，保持默认即可
# host_name = "YOURPCNAME"
# primary_dns = "10.10.10.10"
# dhcp_server = "0.0.0.0"
# bind_ip = "0.0.0.0"
# is_test = true
""";

string[] cliArgs = Environment.GetCommandLineArgs()[1..];

Config? config = null;
string? configSource = null;

try
{
    if (cliArgs.Length >= 1)
    {
        configSource = cliArgs[0];
        config = Config.FromFile(configSource);
    }
    else if (File.Exists(Path.Combine(AppContext.BaseDirectory, "drcom.toml")))
    {
        configSource = Path.Combine(AppContext.BaseDirectory, "drcom.toml");
        config = Config.FromFile(configSource);
    }
    else
    {
        configSource = DrcomConfigStore.ConfigPath;
        config = DrcomConfigStore.TryLoad();
    }
}
catch (Exception ex)
{
    Console.Error.WriteLine($"failed to load config: {ex.Message}");
    return 1;
}

if (config is null)
{
    Console.Error.WriteLine($"config file not found: {configSource}");
    Console.Error.WriteLine("sample config:");
    Console.Error.WriteLine(SampleConfig);
    return 1;
}

Console.WriteLine($"loaded config: {configSource}");
Console.WriteLine($"auth svr: {config.Server}");
Console.WriteLine($"username: {config.Username}");
Console.WriteLine($"mac: {config.Mac}");
Console.WriteLine($"bind ip: {config.BindIp}");
Console.WriteLine("按 q 键可注销当前会话。");

try
{
    using var client = new Client(config) { Verbose = config.IsTest };
    client.Run();
}
catch (Exception ex)
{
    Console.Error.WriteLine($"运行失败: {ex.Message}");
    return 1;
}

Console.WriteLine("已退出。");
return 0;
