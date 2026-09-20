using System.Net;
using System.Net.Sockets;
using System.Text;

namespace DrcomClient;

/// <summary>
/// Dr.COM 客户端：封装 UDP socket、Challenge、Login、KeepAlive 与注销流程。
/// </summary>
/// <remarks>
/// <see cref="Run"/> 会额外启动键盘监听线程（按 <c>q</c> 询问是否注销，再按 <c>y</c> 确认）；
/// <see cref="RunUntilStopped"/> 则不读键盘，由宿主通过 <see cref="RequestStop"/> 控制。
/// </remarks>
public sealed class Client : IDisposable
{
    private const int ServerPort = 61440;
    private const int LocalPort = 61440;
    private const int RecvBufSize = 1024;
    private const int RecvTimeoutMs = 3000;

    private readonly Config _config;
    private readonly Socket _socket;
    private readonly IPEndPoint _server;
    private readonly ManualResetEventSlim _stop = new(false);
    private bool _disposed;

    /// <summary>是否输出详细报文日志。</summary>
    public bool Verbose { get; set; }

    /// <summary>根据配置创建客户端并绑定本地 UDP 端口 61440。</summary>
    public Client(Config config)
    {
        _config = config;
        _server = new IPEndPoint(IPAddress.Parse(config.Server), ServerPort);
        _socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        _socket.Bind(new IPEndPoint(IPAddress.Parse(config.BindIp), LocalPort));
        _socket.ReceiveTimeout = RecvTimeoutMs;
    }

    /// <summary>请求停止保活循环（线程安全，可从任意线程调用）。</summary>
    public void RequestStop() => _stop.Set();

    /// <summary>是否已请求停止。</summary>
    public bool IsStopRequested => _stop.IsSet;

    /// <summary>运行完整的认证与保活流程（CLI 行为，含键盘 <c>q</c>/<c>y</c> 注销）。</summary>
    public void Run()
    {
        var keyboard = new Thread(KeyboardListener) { IsBackground = true, Name = "keyboard" };
        keyboard.Start();
        RunUntilStopped();
    }

    /// <summary>运行认证与保活流程，直到收到停止请求，然后注销。</summary>
    public void RunUntilStopped()
    {
        var (salt, packageTail) = Login();
        EmptySocketBuffer();
        KeepAlive1(salt, packageTail);
        KeepAlive2(salt, packageTail);

        if (_stop.IsSet)
        {
            Console.WriteLine("\n正在注销...");
            Logout();
            Console.WriteLine("注销完成。");
        }
    }

    /// <summary>发送注销报文并等待响应（超时视为已离线，不视为错误）。</summary>
    public void Logout()
    {
        byte[] usr = Encoding.UTF8.GetBytes(_config.Username);
        byte[] packet = Protocol.Logout(usr, _config.ParseMac(), _config);
        _socket.SendTo(packet, _server);
        Log($"[logout] send {Hex(packet)}");

        try
        {
            byte[] data = ReceiveFrom();
            if (data.Length > 0)
            {
                Console.WriteLine($"注销响应: {Hex(data)}");
            }
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.TimedOut)
        {
            Console.WriteLine("未收到注销响应（可能已离线）");
        }
    }

    private byte[] Challenge(long ran)
    {
        while (true)
        {
            ushort r = (ushort)(ran & 0xFFFF);
            var packet = new List<byte> { 0x01, 0x02, (byte)(r & 0xFF), (byte)(r >> 8), 0x09 };
            packet.AddRange(new byte[15]);
            byte[] pkt = packet.ToArray();

            Log($"[challenge] send {Hex(pkt)}");
            _socket.SendTo(pkt, _server);

            try
            {
                byte[] data = ReceiveFrom();
                Log($"[challenge] recv {Hex(data)}");
                if (data.Length < 8)
                {
                    throw new IOException("challenge response too short");
                }
                if (data[0] != 2)
                {
                    throw new IOException("challenge failed");
                }
                Log("[challenge] challenge packet sent.");
                return data[4..8];
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.TimedOut)
            {
                Log("[challenge] timeout, retrying...");
            }
        }
    }

    private (byte[] Salt, byte[] Tail) Login()
    {
        byte[] usr = Encoding.UTF8.GetBytes(_config.Username);
        byte[] pwd = Encoding.UTF8.GetBytes(_config.Password);
        ulong mac = _config.ParseMac();

        long ran = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + Random.Shared.Next(0x0f, 0x100);
        byte[] salt = Challenge(ran);
        Log($"[salt] {Hex(salt)}");

        byte[] packet = Protocol.Mkpkt(salt, usr, pwd, mac, _config);
        Log($"[login] send {Hex(packet)}");
        _socket.SendTo(packet, _server);

        byte[] data = ReceiveFrom();
        Log($"[login] recv {Hex(data)}");
        if (data.Length == 0 || data[0] != 4)
        {
            throw new IOException("login failed");
        }
        Log("[login] logged in");

        var tail = new byte[16];
        if (data.Length >= 39)
        {
            Array.Copy(data, 23, tail, 0, 16);
        }
        return (salt, tail);
    }

    private void KeepAlive1(byte[] salt, byte[] tail)
    {
        byte[] pwd = Encoding.UTF8.GetBytes(_config.Password);
        ushort ts = (ushort)(DateTimeOffset.UtcNow.ToUnixTimeSeconds() % 0xFFFF);

        var data = new List<byte> { 0xff };
        data.AddRange(Protocol.Md5Sum(new byte[] { 0x03, 0x01 }, salt, pwd));
        data.AddRange(new byte[] { 0x00, 0x00, 0x00 });
        data.AddRange(tail);
        data.Add((byte)(ts >> 8));   // 大端
        data.Add((byte)(ts & 0xFF));
        data.AddRange(new byte[4]);

        byte[] pkt = data.ToArray();
        Log($"[keep_alive1] send {Hex(pkt)}");
        _socket.SendTo(pkt, _server);

        while (true)
        {
            byte[] recv = ReceiveFrom();
            Log($"[keep_alive1] recv {Hex(recv)}");
            if (recv.Length > 0 && recv[0] == 7)
            {
                break;
            }
        }
    }

    private void KeepAlive2(byte[] salt, byte[] packageTail)
    {
        byte[] hostIp = Config.ParseIp(_config.HostIp);
        byte[] kaVersion = Config.ParseHex(_config.KeepAliveVersion);

        long ran = Random.Shared.Next(0, 0x10000) + Random.Shared.Next(1, 11);
        byte svrNum = 0;

        byte[] packet = Protocol.KeepAlivePackageBuilder(svrNum, new byte[4], 1, first: true, hostIp, kaVersion);

        // 第一阶段：等待正常响应；若收到文件包则递增 svr_num 重发
        while (true)
        {
            Log($"[keep-alive2] send1 {Hex(packet)}");
            _socket.SendTo(packet, _server);
            byte[] data = ReceiveFrom();
            Log($"[keep-alive2] recv1 {Hex(data)}");

            if (StartsWith(data, new byte[] { 0x07, 0x00, 0x28, 0x00 }) ||
                StartsWith(data, new byte[] { 0x07, svrNum, 0x28, 0x00 }))
            {
                break;
            }

            if (data.Length > 2 && data[0] == 0x07 && data[2] == 0x10)
            {
                Log("[keep-alive2] recv file, resending..");
                svrNum++;
                packet = Protocol.KeepAlivePackageBuilder(svrNum, new byte[4], 1, first: false, hostIp, kaVersion);
            }
            else
            {
                Log($"[keep-alive2] recv1/unexpected {Hex(data)}");
            }
        }

        // 第二阶段：type=1，取回新的 tail
        ran += Random.Shared.Next(1, 11);
        packet = Protocol.KeepAlivePackageBuilder(svrNum, new byte[4], 1, first: false, hostIp, kaVersion);
        Log($"[keep-alive2] send2 {Hex(packet)}");
        _socket.SendTo(packet, _server);

        var tail = new byte[4];
        while (true)
        {
            byte[] data = ReceiveFrom();
            Log($"[keep-alive2] recv2 {Hex(data)}");
            if (data.Length > 0 && data[0] == 7)
            {
                svrNum++;
                if (data.Length >= 20)
                {
                    Array.Copy(data, 16, tail, 0, 4);
                }
                break;
            }
        }

        // 第三阶段：type=3
        ran += Random.Shared.Next(1, 11);
        packet = Protocol.KeepAlivePackageBuilder(svrNum, tail, 3, first: false, hostIp, kaVersion);
        Log($"[keep-alive2] send3 {Hex(packet)}");
        _socket.SendTo(packet, _server);

        while (true)
        {
            byte[] data = ReceiveFrom();
            Log($"[keep-alive2] recv3 {Hex(data)}");
            if (data.Length > 0 && data[0] == 7)
            {
                svrNum++;
                if (data.Length >= 20)
                {
                    Array.Copy(data, 16, tail, 0, 4);
                }
                break;
            }
        }

        Log("[keep-alive2] keep-alive2 loop was in daemon.");

        // 持续保活循环
        byte i = svrNum;
        while (!_stop.IsSet)
        {
            try
            {
                ran += Random.Shared.Next(1, 11);
                packet = Protocol.KeepAlivePackageBuilder(i, tail, 1, first: false, hostIp, kaVersion);
                Log($"[keep_alive2] send {i} {Hex(packet)}");
                _socket.SendTo(packet, _server);
                byte[] data = ReceiveFrom();
                if (data.Length >= 20)
                {
                    Array.Copy(data, 16, tail, 0, 4);
                }

                ran += Random.Shared.Next(1, 11);
                packet = Protocol.KeepAlivePackageBuilder((byte)(i + 1), tail, 3, first: false, hostIp, kaVersion);
                Log($"[keep_alive2] send {i + 1} {Hex(packet)}");
                _socket.SendTo(packet, _server);
                data = ReceiveFrom();
                if (data.Length >= 20)
                {
                    Array.Copy(data, 16, tail, 0, 4);
                }

                i = (byte)((i + 2) % 0xFF);

                // 分片等待，及时响应停止请求
                for (int s = 0; s < 20; s++)
                {
                    if (_stop.Wait(1000))
                    {
                        return;
                    }
                }

                KeepAlive1(salt, packageTail);
            }
            catch (SocketException)
            {
                // 网络异常时继续循环，与原版行为一致
            }
        }
    }

    private void EmptySocketBuffer()
    {
        Log("starting to empty socket buffer");
        var buffer = new byte[RecvBufSize];
        EndPoint ep = new IPEndPoint(IPAddress.Any, 0);

        while (true)
        {
            try
            {
                int len = _socket.ReceiveFrom(buffer, ref ep);
                Log($"received sth unexpected {Hex(buffer[..len])}");
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.TimedOut)
            {
                break;
            }
        }

        Log("emptied");
    }

    private byte[] ReceiveFrom()
    {
        var buffer = new byte[RecvBufSize];
        EndPoint ep = new IPEndPoint(IPAddress.Any, 0);
        int len = _socket.ReceiveFrom(buffer, ref ep);

        var remote = (IPEndPoint)ep;
        if (!remote.Address.Equals(_server.Address))
        {
            throw new IOException($"wrong server address: {remote}");
        }

        return buffer[..len];
    }

    private void KeyboardListener()
    {
        try
        {
            if (Console.IsInputRedirected)
            {
                return;
            }

            while (true)
            {
                ConsoleKeyInfo key = Console.ReadKey(intercept: true);
                if (key.KeyChar is 'q' or 'Q')
                {
                    Console.WriteLine();
                    Console.Write("是否注销？(y/n): ");
                    ConsoleKeyInfo confirm = Console.ReadKey(intercept: true);
                    Console.WriteLine();

                    if (confirm.KeyChar is 'y' or 'Y')
                    {
                        RequestStop();
                        return;
                    }

                    Console.WriteLine("取消注销，继续保活...");
                }
            }
        }
        catch (InvalidOperationException)
        {
            // 无交互式控制台时忽略
        }
    }

    private void Log(string message)
    {
        if (Verbose)
        {
            Console.WriteLine(message);
        }
    }

    private static string Hex(byte[] data) => Convert.ToHexStringLower(data);

    private static bool StartsWith(byte[] data, byte[] prefix)
    {
        if (data.Length < prefix.Length)
        {
            return false;
        }
        for (int i = 0; i < prefix.Length; i++)
        {
            if (data[i] != prefix[i])
            {
                return false;
            }
        }
        return true;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        _stop.Dispose();
        _socket.Dispose();
    }
}
