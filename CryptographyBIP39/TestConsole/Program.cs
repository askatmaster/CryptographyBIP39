using CryptographyBIP39;
using TestConsole;

// Basic application

var b39 = new BIP39();
var binaryEntropy = string.Join("", b39.EntropyBytes.Select(b => Convert.ToString(b, 2).PadLeft(8, '0')));
Console.WriteLine("EntropyBytesBinary: " + binaryEntropy);

Console.Write("EntropyBytes: ");
foreach (var i in b39.EntropyBytes)
    Console.Write(i);
Console.WriteLine();

Console.WriteLine("Sentence: " + b39.MnemonicSentence);
Console.WriteLine("Seed: " + b39.SeedBytesHexString);
Console.WriteLine("Language: " + b39.WordlistLanguage);
Console.WriteLine("WordCount: " + b39.WordCountFromEntropy);

// =========================================================================================================================================================

// An example of obtaining 12 words from a 128 bit string using the basic implementation of the algorithm

var numberBits = TestAlgoritm.GetRandomBitsString(128);
Console.WriteLine(numberBits);
Console.WriteLine();

var hash = TestAlgoritm.GetNumberHash(numberBits);
Console.WriteLine(hash);
Console.WriteLine();

var dictionary = TestAlgoritm.ParseBinaryToPositinDictionary(numberBits, hash);
foreach (var record in dictionary)
    Console.WriteLine(record.Key + " " + record.Value);

var words = TestAlgoritm.GetMnemonicWords(dictionary);

Console.WriteLine();
Console.WriteLine(string.Join(" ", words));