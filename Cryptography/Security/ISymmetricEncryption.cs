using System.Threading.Tasks;

namespace Cryptography.Security
{
    public interface ISymmetricEncryption
    {
        Task<string> EncryptAsync(string plainText);
        Task<string> DecryptAsync(string cipherText);
    }
}
