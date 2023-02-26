using System.Security.Cryptography;
using System.Text;
using CryptographyBIP39.Wordlists;
namespace TestConsole;

public static class TestAlgoritm
{
    public static string GetRandomBitsString(int bits)
    {
        if (bits % 8 != 0)
            throw new Exception("Only multiples of 8 are allowed");

        var random = new Random();
        var sb = new StringBuilder();

        for (var i = 0; i < bits; i++)
        {
            var randomNumber = random.Next(0, 2);
            sb.Append(randomNumber);
        }

        return sb.ToString();
    }

    public static string GetNumberHash(string stringNumber)
    {
        // Convert the binary number to a byte array
        var binaryBytes = new byte[(stringNumber.Length + 7) / 8];
        var byteIndex = 0;
        var bitIndex = 0;

        foreach (var c in stringNumber)
        {
            if (c == '1')
                binaryBytes[byteIndex] |= (byte)(0x80 >> bitIndex);
            bitIndex++;

            if (bitIndex != 8)
                continue;

            byteIndex++;
            bitIndex = 0;
        }

        // Compute the SHA256 hash of the byte array
        byte[] hashBytes;
        using (var sha256 = SHA256.Create())
            hashBytes = sha256.ComputeHash(binaryBytes);

        return string.Join("", hashBytes.Select(byt => Convert.ToString(byt, 2).PadLeft(8, '0')));
    }

    public static Dictionary<string, int> ParseBinaryToPositinDictionary(string bynaryString, string? bynaryStringHash = null)
    {
        var partSize = 11;
        var dictionary = new Dictionary<string, int>();

        if(!string.IsNullOrEmpty(bynaryStringHash))
            bynaryString += bynaryStringHash[..4];

        for (var i = 0; i < bynaryString.Length; i += partSize)
        {
            var part = bynaryString.Substring(i, Math.Min(partSize, bynaryString.Length - i));

            var wordIndex = Convert.ToInt16(part, 2);

            switch(part.Length)
            {
                case 11:
                    dictionary.Add(part, wordIndex);

                    break;
                default:
                    throw new Exception("An amount not matching 11 bits was detected");
            }
        }

        return dictionary;
    }

    public static List<string> GetMnemonicWords(Dictionary<string, int> dictionary)
    {
        var english = new English();

        return dictionary.Select(index => english.GetWordAtIndex(index.Value)).ToList();
    }

    public static string StringToBinary(string inputString)
    {
        var bytes = Encoding.UTF8.GetBytes(inputString);

        var binaryString = bytes.Aggregate("", (current, b) => current + Convert.ToString(b, 2).PadLeft(8, '0'));

        return binaryString;
    }
}