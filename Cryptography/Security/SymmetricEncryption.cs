using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Cryptography.Security
{
    public class SymmetricEncryption : ISymmetricEncryption
    {
        private readonly string _secretKey;
        private readonly string _initializationVector;

        public SymmetricEncryption(string secretKey, string initializationVector)
        {
            _secretKey = secretKey;
            _initializationVector = initializationVector;
        }

        public async Task<string> EncryptAsync(string plainText)
        {
            using (var aes = Aes.Create())
            {
                SetKeyAndIV(aes);

                var encryptor = aes.CreateEncryptor();
                using (var memoryStream = new MemoryStream())
                {
                    using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        using (var streamWriter = new StreamWriter(cryptoStream))
                        {
                            await streamWriter.WriteAsync(plainText);
                        }

                        var encryptedArray = memoryStream.ToArray();
                        var cipherText = Convert.ToBase64String(encryptedArray);
                        return cipherText;
                    }
                }
            }
        }

        public async Task<string> DecryptAsync(string cipherText)
        {
            using (var aes = Aes.Create())
            {
                SetKeyAndIV(aes);

                var decryptor = aes.CreateDecryptor();
                var cipherTextBytes = Convert.FromBase64String(cipherText);
                using (var memoryStream = new MemoryStream(cipherTextBytes))
                {
                    using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                    {
                        using (var streamReader = new StreamReader(cryptoStream))
                        {
                            var plainText = await streamReader.ReadToEndAsync();
                            return plainText;
                        }
                    }
                }
            }
        }

        private void SetKeyAndIV(Aes aes)
        {
            aes.Key = Encoding.UTF8.GetBytes(_secretKey);
            aes.IV = Encoding.UTF8.GetBytes(_initializationVector);
        }
    }
}
