using System.Collections;
using System.Security.Cryptography;
using System.Text;
namespace CryptographyBIP39;

/// <summary>
/// A Library that provides common functionality between my other Bitcoin Modules
/// </summary>
public static class Utilities
{
    /// <summary>
    /// Calculates RIPEMD160(SHA256(input)). This is used in Address calculations.
    /// </summary>
    public static byte[] Sha256Hash160(byte[] input)
    {
        var sha256Hash = SHA256.HashData(input);

        return RIPEMD160.ComputeHash(sha256Hash);
    }

    /// <summary>
    /// Calculates the SHA256 32 byte checksum of the input bytes
    /// </summary>
    /// <param name="input">bytes input to get checksum</param>
    /// <param name="offset">where to start calculating checksum</param>
    /// <param name="length">length of the input bytes to perform checksum on</param>
    /// <returns>32 byte array checksum</returns>
    public static byte[] Sha256Digest(byte[] input, int offset, int length)
    {
        using (var sha256 = SHA256.Create())
        {
            var hash = sha256.ComputeHash(input, offset, length);
            return hash;
        }
    }

    /// <summary>
    /// Turns a byte array into a Hex encoded string
    /// </summary>
    /// <param name="bytes">The bytes to encode to hex</param>
    /// <param name="upperCase"></param>
    /// <returns>The hex encoded representation of the bytes</returns>
    public static string BytesToHexString(byte[] bytes, bool upperCase = false)
    {
        return string.Concat(upperCase ? bytes.Select(byteb => byteb.ToString("X2")).ToArray() : bytes.Select(byteb => byteb.ToString("x2")).ToArray());
    }

    /// <summary>
    /// Calculates the 64 byte checksum in accordance with HMAC-SHA512
    /// </summary>
    /// <param name="input">The bytes to derive the checksum from</param>
    /// <param name="offset">Where to start calculating checksum in the input bytes</param>
    /// <param name="length">Length of buytes to use to calculate checksum</param>
    /// <param name="hmacKey">HMAC Key used to generate the checksum (note differing HMAC Keys provide unique checksums)</param>
    /// <returns></returns>
    public static byte[] HmacSha512Digest(byte[] input, int offset, int length, byte[] hmacKey)
    {
        using (var hmac = new HMACSHA512(hmacKey))
        {
            var output = hmac.ComputeHash(input, offset, length);
            return output;
        }
    }

    /// <summary>
    /// Safely get Crypto Random byte array at the size you desire.
    /// </summary>
    /// <param name="size">Size of the crypto random byte array to build</param>
    /// <returns>A byte array of completely random bytes</returns>
    public static byte[] GetRandomBytes(int size)
    {
        using (var rng = RandomNumberGenerator.Create())
        {
            var bytes = new byte[size];
            rng.GetBytes(bytes);
            return bytes;
        }
    }

    /// <summary>
    /// Safely get Crypto Random byte array at the size you desire, made this async version because can take 500ms to complete and so this allows non-blocking for the 500ms.
    /// </summary>
    /// <param name="size">Size of the crypto random byte array to build</param>
    /// <returns>A byte array of completely random bytes</returns>
    public static async Task<byte[]> GetRandomBytesAsync(int size)
    {
        return await Task.Run(() => GetRandomBytes(size));
    }

    /// <summary>
    /// Merges two byte arrays
    /// </summary>
    /// <param name="source1">first byte array</param>
    /// <param name="source2">second byte array</param>
    /// <returns>A byte array which contains source1 bytes followed by source2 bytes</returns>
    public static byte[] MergeByteArrays(byte[] source1, byte[] source2)
    {
        var buffer = new byte[source1.Length + source2.Length];
        Buffer.BlockCopy(source1, 0, buffer, 0, source1.Length);
        Buffer.BlockCopy(source2, 0, buffer, source1.Length, source2.Length);

        return buffer;
    }

    /// <summary>
    /// This switches the Endianess of the provided byte array, byte per byte we do bit swappy.
    /// </summary>
    /// <param name="bytes">Bytes to change endianess of</param>
    /// <returns>Bytes with endianess swapped</returns>
    public static byte[] SwapEndianBytes(byte[] bytes)
    {
        var output = new byte[bytes.Length];

        var index = 0;

        foreach (var b in bytes)
        {
            byte[] ba = { b };
            var bits = new BitArray(ba);

            var newByte = 0;
            if (bits.Get(7))
                newByte++;
            if (bits.Get(6))
                newByte += 2;
            if (bits.Get(5))
                newByte += 4;
            if (bits.Get(4))
                newByte += 8;
            if (bits.Get(3))
                newByte += 16;
            if (bits.Get(2))
                newByte += 32;
            if (bits.Get(1))
                newByte += 64;
            if (bits.Get(0))
                newByte += 128;

            output[index] = Convert.ToByte(newByte);

            index++;
        }

        //I love lamp
        return output;
    }

    /// <summary>
    /// Normalises a string with NKFD normal form
    /// </summary>
    /// <param name="toNormalise">String to be normalised</param>
    /// <returns>Normalised string</returns>
    public static string NormaliseStringNfkd(string toNormalise)
    {
        return toNormalise.Trim().Normalize(NormalizationForm.FormKD);
    }
}