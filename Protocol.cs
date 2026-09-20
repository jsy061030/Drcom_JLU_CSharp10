using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace DrcomClient;

/// <summary>
/// Dr.COM 协议底层实现，对应原 Python 脚本中的各个报文构造函数。
/// </summary>
public static class Protocol
{
    /// <summary>计算 MD5 摘要（对多个字节段拼接后计算）。</summary>
    public static byte[] Md5Sum(params byte[][] parts)
    {
        int total = 0;
        foreach (byte[] p in parts)
        {
            total += p.Length;
        }

        var buffer = new byte[total];
        int offset = 0;
        foreach (byte[] p in parts)
        {
            Buffer.BlockCopy(p, 0, buffer, offset, p.Length);
            offset += p.Length;
        }

        return MD5.HashData(buffer);
    }

    /// <summary>
    /// 将整数转换为最简偶数长度 hex 字节串（对应 Python 的 <c>dump()</c>）。
    /// </summary>
    /// <remarks><c>0 -&gt; [0x00]</c>、<c>255 -&gt; [0xff]</c>、<c>256 -&gt; [0x01, 0x00]</c>。</remarks>
    public static byte[] Dump(ulong n)
    {
        string hex = n.ToString("x", CultureInfo.InvariantCulture);
        if (hex.Length % 2 != 0)
        {
            hex = "0" + hex;
        }

        var result = new byte[hex.Length / 2];
        for (int i = 0; i < result.Length; i++)
        {
            result[i] = byte.Parse(hex.AsSpan(i * 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        }
        return result;
    }

    /// <summary>Dr.COM 密码混淆算法，对应 Python 的 <c>ror()</c>。</summary>
    public static byte[] Ror(byte[] md5, byte[] pwd)
    {
        var result = new byte[pwd.Length];
        for (int i = 0; i < pwd.Length; i++)
        {
            int x = md5[i] ^ pwd[i];
            result[i] = (byte)(((x << 3) & 0xFF) + (x >> 5));
        }
        return result;
    }

    /// <summary>
    /// Dr.COM 报文校验和，对应 Python 的 <c>checksum()</c>。
    /// </summary>
    /// <remarks>
    /// 为与原脚本输出逐字节一致，这里**刻意复刻**了 Python
    /// <c>re.findall(b'....', s)</c> 的行为：正则中的 <c>.</c> 默认不匹配换行字节
    /// <c>0x0A</c>，因此任何含 <c>0x0A</c> 的 4 字节窗口都会匹配失败，扫描位置右移
    /// 1 字节重新对齐。
    ///
    /// 由于本机 DNS（如 <c>10.10.10.10</c>）会产生 <c>0a</c> 字节，该差异会实际影响
    /// 结果，故必须保留此行为才能与原客户端一致。若服务器不校验该字段，则无影响。
    /// </remarks>
    public static byte[] Checksum(byte[] data)
    {
        uint ret = 1234;
        int pos = 0;
        while (pos + 4 <= data.Length)
        {
            bool hasNewline =
                data[pos] == 0x0A || data[pos + 1] == 0x0A ||
                data[pos + 2] == 0x0A || data[pos + 3] == 0x0A;

            if (hasNewline)
            {
                // 匹配失败：右移 1 字节重新尝试对齐
                pos++;
                continue;
            }

            uint word = (uint)(data[pos] | (data[pos + 1] << 8) | (data[pos + 2] << 16) | (data[pos + 3] << 24));
            ret ^= word;
            pos += 4;
        }

        ret = unchecked(1968u * ret);
        return new[] { (byte)ret, (byte)(ret >> 8), (byte)(ret >> 16), (byte)(ret >> 24) };
    }

    /// <summary>构造 keep-alive 报文。</summary>
    public static byte[] KeepAlivePackageBuilder(
        byte number, byte[] tail, byte pkgType, bool first, byte[] hostIp, byte[] keepAliveVersion)
    {
        var data = new List<byte> { 0x07, number, 0x28, 0x00, 0x0b, pkgType };
        if (first)
        {
            data.AddRange(new byte[] { 0x0f, 0x27 });
        }
        else
        {
            data.AddRange(keepAliveVersion);
        }

        data.AddRange(new byte[] { 0x2f, 0x12 });
        data.AddRange(new byte[6]);
        data.AddRange(tail);
        data.AddRange(new byte[4]);

        if (pkgType == 3)
        {
            data.AddRange(new byte[4]); // CRC 置零
            data.AddRange(hostIp);      // 本机 IP
            data.AddRange(new byte[8]);
        }
        else
        {
            data.AddRange(new byte[16]);
        }

        return data.ToArray();
    }

    /// <summary>
    /// 构造登录报文，对应 Python 的 <c>mkpkt()</c>。
    /// </summary>
    public static byte[] Mkpkt(byte[] salt, byte[] usr, byte[] pwd, ulong mac, Config config)
    {
        var data = new List<byte> { 0x03, 0x01, 0x00, (byte)(usr.Length + 20) };

        byte[] md51 = Md5Sum(new byte[] { 0x03, 0x01 }, salt, pwd);
        data.AddRange(md51);

        // 用户名（不足 36 字节右补零）
        data.AddRange(PadRight(usr, 36));

        data.AddRange(Config.ParseHex(config.ControlCheckStatus));
        data.AddRange(Config.ParseHex(config.AdapterNum));

        // mac xor md51[0:6]
        ulong md51Part = 0;
        for (int i = 0; i < 6; i++)
        {
            md51Part = (md51Part << 8) | md51[i];
        }
        data.AddRange(PadLeft(Dump(md51Part ^ mac), 6));

        // md52
        data.AddRange(Md5Sum(new byte[] { 0x01 }, pwd, salt, new byte[4]));

        data.Add(0x01);
        data.AddRange(Config.ParseIp(config.HostIp));
        data.AddRange(new byte[12]); // 备用 IP 2~4

        // md53：取前 8 字节
        byte[] md53 = Md5Sum(data.ToArray(), new byte[] { 0x14, 0x00, 0x07, 0x0b });
        data.AddRange(md53[..8]);

        data.AddRange(Config.ParseHex(config.IpDog));
        data.AddRange(new byte[4]);
        data.AddRange(PadRight(Encoding.UTF8.GetBytes(config.HostName), 32));

        data.AddRange(Config.ParseIp(config.PrimaryDns));
        data.AddRange(Config.ParseIp(config.DhcpServer));
        data.AddRange(new byte[4]); // 备用 DNS
        data.AddRange(new byte[8]); // 分隔符

        // OS 与 DrCOM 魔数字段
        data.AddRange(new byte[] { 0x94, 0x00, 0x00, 0x00 });
        data.AddRange(new byte[] { 0x06, 0x00, 0x00, 0x00 });
        data.AddRange(new byte[] { 0x02, 0x00, 0x00, 0x00 });
        data.AddRange(new byte[] { 0xf0, 0x23, 0x00, 0x00 });
        data.AddRange(new byte[] { 0x02, 0x00, 0x00, 0x00 });
        data.AddRange(new byte[] { 0x44, 0x72, 0x43, 0x4f, 0x4d, 0x00, 0xcf, 0x07, 0x68 }); // "DrCOM\0\xcf\x07\x68"
        data.AddRange(new byte[55]);
        data.AddRange(Encoding.ASCII.GetBytes("3dc79f5212e8170acfa9ec95f1d74916542be7b1"));
        data.AddRange(new byte[24]);

        data.AddRange(Config.ParseHex(config.AuthVersion));
        data.Add(0x00);
        data.Add((byte)pwd.Length);
        data.AddRange(Ror(md51, pwd));
        data.AddRange(new byte[] { 0x02, 0x0c });

        // 校验和
        var chkInput = new List<byte>(data);
        chkInput.AddRange(new byte[] { 0x01, 0x26, 0x07, 0x11, 0x00, 0x00 });
        chkInput.AddRange(Dump(mac));
        data.AddRange(Checksum(chkInput.ToArray()));

        data.AddRange(new byte[] { 0x00, 0x00 });
        data.AddRange(Dump(mac));

        // 密码非 16 字节时的特殊填充
        if (pwd.Length != 16)
        {
            data.AddRange(new byte[pwd.Length / 4]);
        }

        data.AddRange(new byte[] { 0x60, 0xa2 });
        data.AddRange(new byte[28]);

        return data.ToArray();
    }

    /// <summary>
    /// 构造注销报文（命令字 <c>0x06</c>）。
    /// </summary>
    /// <remarks>
    /// 原 Python 脚本未实现注销，该格式依据通用 Dr.COM 实现推导，
    /// 若服务器不接受请对照抓包调整。
    /// </remarks>
    public static byte[] Logout(byte[] usr, ulong mac, Config config)
    {
        var data = new List<byte> { 0x06, 0x01, 0x00, (byte)(usr.Length + 20) };
        data.AddRange(new byte[16]); // 登录报文中为 md5，注销时置零
        data.AddRange(PadRight(usr, 36));
        data.AddRange(Config.ParseHex(config.ControlCheckStatus));
        data.AddRange(Config.ParseHex(config.AdapterNum));
        data.AddRange(PadLeft(Dump(mac), 6));
        return data.ToArray();
    }

    /// <summary>不足 <paramref name="size"/> 字节时右补零，超过则原样返回。</summary>
    private static byte[] PadRight(byte[] value, int size)
    {
        if (value.Length >= size)
        {
            return value;
        }

        var result = new byte[size];
        Buffer.BlockCopy(value, 0, result, 0, value.Length);
        return result;
    }

    /// <summary>不足 <paramref name="size"/> 字节时左补零，超过则原样返回。</summary>
    private static byte[] PadLeft(byte[] value, int size)
    {
        if (value.Length >= size)
        {
            return value;
        }

        var result = new byte[size];
        Buffer.BlockCopy(value, 0, result, size - value.Length, value.Length);
        return result;
    }
}
