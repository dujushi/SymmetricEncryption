using Cryptography.Security;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;

namespace Cryptography.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class SymmetricEncryptionController : ControllerBase
    {
        private readonly ISymmetricEncryption _symmetricEncryption;

        public SymmetricEncryptionController(ISymmetricEncryption symmetricEncryption)
        {
            _symmetricEncryption = symmetricEncryption;
        }

        [HttpGet("Encrypt/{plainText}")]
        public async Task<ActionResult<string>> Encrypt(string plainText)
        {
            var cipherText = await _symmetricEncryption.EncryptAsync(plainText);
            return cipherText;
        }

        [HttpGet("Decrypt/{cipherText}")]
        public async Task<ActionResult<string>> Decrypt(string cipherText)
        {
            var plainText = await _symmetricEncryption.DecryptAsync(cipherText);
            return plainText;
        }
    }
}
