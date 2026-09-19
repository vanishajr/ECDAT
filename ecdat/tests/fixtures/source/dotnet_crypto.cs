using System.Security.Cryptography;

public static class DotNetCrypto
{
    public static byte[] Encrypt(byte[] key, byte[] data)
    {
        using var aes = Aes.Create();
        return aes.EncryptCbc(data, key);
    }

    public static byte[] Sha256(byte[] data)
    {
        using var sha = SHA256.Create();
        return sha.ComputeHash(data);
    }

    public static byte[] Derive(byte[] ikm, byte[] salt)
    {
        return Rfc2898DeriveBytes.Pbkdf2(ikm, salt, 100000,
            HashAlgorithmName.SHA256, 32);
    }
}
