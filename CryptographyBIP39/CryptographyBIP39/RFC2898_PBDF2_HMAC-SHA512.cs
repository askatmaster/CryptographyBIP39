namespace CryptographyBIP39;

/// <summary>
/// Implementation of the Rfc2898 PBKDF2 specification located here http://www.ietf.org/rfc/rfc2898.txt using HMACSHA512 but modified as opposed to PWDTKto match the BIP39 test vectors
/// Using BouncyCastle for the HMAC-SHA512 instead of Microsoft implementation
/// NOTE NOT IDENTICLE TO PWDTK (PWDTK is concatenating password and salt together before hashing the concatenated byte block, this is simply hashing the salt as what we are told to do in BIP39, yes the mnemonic sentence is provided as the hmac key)
/// </summary>
public class RFC2898_PBKDF2_HMACSHA512
{
    //I made the variable names match the definition in RFC2898 - PBKDF2 where possible, so you can trace the code functionality back to the specification
    private readonly byte[] P;
    private readonly byte[] S;
    private readonly int c;
    private int dkLen;
    private const int CMinIterations = 2048;

    //Length of the Hash Digest Output - 512 bits - 64 bytes
    private const int hLen = 64;
    /// <summary>
    /// Constructor to create Rfc2898_pbkdf2_hmacsha512 object ready to perform Rfc2898 PBKDF2 functionality
    /// </summary>
    /// <param name="password">The Password to be hashed and is also the HMAC key</param>
    /// <param name="salt">Salt to be concatenated with the password</param>
    /// <param name="iterations">Number of iterations to perform HMACSHA Hashing for PBKDF2</param>
    public RFC2898_PBKDF2_HMACSHA512(byte[] password, byte[] salt, int iterations = CMinIterations)
    {
        P = password;
        S = salt;
        c = iterations;
    }

    #region Public Members And Static Methods
    /// <summary>
    /// Derive Key Bytes using PBKDF2 specification listed in Rfc2898 and HMACSHA512 as the underlying PRF (Psuedo Random Function)
    /// </summary>
    /// <param name="keyLength">Length in Bytes of Derived Key</param>
    /// <returns>Derived Key</returns>
    public byte[] GetDerivedKeyBytes_PBKDF2_HMACSHA512(int keyLength)
    {
        //no need to throw exception for dkLen too long as per spec because dkLen cannot be larger than Int32.MaxValue so not worth the overhead to check
        dkLen = keyLength;

        var l = Math.Ceiling((double)dkLen / hLen);

        var finalBlock = Array.Empty<byte>();

        for (var i = 1; i <= l; i++)

            //Concatenate each block from F into the final block (T_1..T_l)
            finalBlock = Utilities.MergeByteArrays(finalBlock, F(P, S, c, i));

        //returning DK note r not used as dkLen bytes of the final concatenated block returned rather than <0...r-1> substring of final intermediate block + prior blocks as per spec
        return finalBlock.Take(dkLen).ToArray();
    }

    /// <summary>
    /// A static publicly exposed version of GetDerivedKeyBytes_PBKDF2_HMACSHA512 which matches the exact specification in Rfc2898 PBKDF2 using HMACSHA512
    /// </summary>
    /// <param name="P">Password passed as a Byte Array</param>
    /// <param name="S">Salt passed as a Byte Array</param>
    /// <param name="c">Iterations to perform the underlying PRF over</param>
    /// <param name="dkLen">Length of Bytes to return, an AES 256 key wold require 32 Bytes</param>
    /// <returns>Derived Key in Byte Array form ready for use by chosen encryption function</returns>
    public static byte[] PBKDF2(byte[] P, byte[] S, int c = CMinIterations, int dkLen = hLen)
    {
        var rfcObj = new RFC2898_PBKDF2_HMACSHA512(P, S, c);

        return rfcObj.GetDerivedKeyBytes_PBKDF2_HMACSHA512(dkLen);
    }
    #endregion

    //Main Function F as defined in Rfc2898 PBKDF2 spec
    private byte[] F(byte[] P, byte[] S, int c, int i)
    {
        //Salt and Block number Int(i) concatenated as per spec
        var Si = Utilities.MergeByteArrays(S, INT(i));

        //Initial hash (U_1) using password and salt concatenated with Int(i) as per spec
        var temp = PRF(Si, P);

        //Output block filled with initial hash value or U_1 as per spec
        var U_c = temp;

        for (var C = 1; C < c; C++)
        {
            //rehashing the password using the previous hash value as salt as per spec
            temp = PRF(temp, P);

            for (var j = 0; j < temp.Length; j++)

                //xor each byte of the each hash block with each byte of the output block as per spec
                U_c[j] ^= temp[j];
        }

        //return a T_i block for concatenation to create the final block as per spec
        return U_c;
    }

    //PRF function as defined in Rfc2898 PBKDF2 spec
    private byte[] PRF(byte[] S, byte[] hmacKey)
    {
        //HMACSHA512 Hashing, better than the HMACSHA1 in Microsofts implementation ;)
        return Utilities.HmacSha512Digest(S, 0, S.Length, hmacKey);
    }

    //This method returns the 4 octet encoded Int32 with most significant bit first as per spec
    private byte[] INT(int i)
    {
        var I = BitConverter.GetBytes(i);

        //Make sure most significant bit is first
        if (BitConverter.IsLittleEndian)
            Array.Reverse(I);

        return I;
    }
}