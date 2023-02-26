namespace CryptographyBIP39;

public static class RIPEMD160
{
    private const int DigestSize = 20;

    private static readonly uint[] r =
    {
        0x00000000u, 0x5A827999u, 0x6ED9EBA1u, 0x8F1BBCDCu, 0xA953FD4Eu
    };
    private static readonly int[] shift =
    {
        11, 14, 15, 12, 5
    };
    private static readonly int[] index =
    {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
    };

    private static uint F(uint x, uint y, uint z, int i)
    {
        return i switch
        {
            0 => x ^ y ^ z,
            1 => (x & y) | (~x & z),
            2 => (x | ~y) ^ z,
            3 => (x & z) | (y & ~z),
            4 => x ^ (y | ~z),
            _ => 0
        };
    }

    private static uint G(uint x, uint y, uint z, int i)
    {
        return i switch
        {
            0 => (x & y) | (~x & z),
            1 => (x | ~y) ^ z,
            2 => (x & z) | (y & ~z),
            3 => x ^ (y | ~z),
            4 => x | ~y,
            _ => 0
        };
    }

    private static uint RotateLeft(uint x, int n)
    {
        return (x << n) | (x >> (32 - n));
    }

    private static uint[] Pad(byte[] input)
    {
        var len = input.Length;
        var k = 448 - len * 8 % 512;

        if (k <= 0)
            k += 512;
        k += 64;
        var numBlocks = k / 8;
        var padded = new uint[numBlocks];

        for (var i = 0; i < len; i++)
            padded[i / 4] |= (uint)input[i] << (i % 4 * 8);
        padded[len / 4] |= (uint)0x80 << (len % 4 * 8);
        padded[numBlocks - 2] = (uint)(len * 8);

        return padded;
    }

    public static byte[] ComputeHash(byte[] input)
    {
        var padded = Pad(input);
        var numBlocks = padded.Length;
        var h0 = 0x67452301u;
        var h1 = 0xEFCDAB89u;
        var h2 = 0x98BAD0u;
        var h3 = 0x10325476u;
        var h4 = 0xC3D2E1F0u;

        for (var i = 0; i < numBlocks; i += 16)
        {
            uint aa;
            var a = aa = h0;
            uint bb;
            var b = bb = h1;
            uint cc;
            var c = cc = h2;
            uint dd;
            var d = dd = h3;
            uint ee;
            var e = ee = h4;

            for (var j = 0; j < 80; j++)
            {
                var t = RotateLeft(a + F(b, c, d, j) + padded[i + index[j]] + r[j / 16], shift[j / 16]) + e;
                a = e;
                e = d;
                d = RotateLeft(c, 10);
                c = b;
                b = t;
                t = RotateLeft(aa + G(bb, cc, dd, j) + padded[i + index[j]] + r[j / 16 + 5], shift[j / 16]) + ee;
                aa = ee;
                ee = dd;
                dd = RotateLeft(cc, 10);
                cc = bb;
                bb = t;
            }
            h0 += a;
            h1 += b;
            h2 += c;
            h3 += d;
            h4 += e;
        }
        var output = new byte[DigestSize];

        for (var i = 0; i < DigestSize / 4; i++)
        {
            output[i * 4] = (byte)(h0 >> (i * 8));
            output[i * 4 + 1] = (byte)(h1 >> (i * 8));
            output[i * 4 + 2] = (byte)(h2 >> (i * 8));
            output[i * 4 + 3] = (byte)(h3 >> (i * 8));
        }

        return output;
    }
}