using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CryptoPrivacy
{
    public class RSAAlgorithms
    {
        public static string Encrypt(string textToEncrypt, string publicKey, int keysize)
        {
            var bytesToEncrypt = Encoding.UTF8.GetBytes(textToEncrypt);

            using (var RSAEncryption = new RSACryptoServiceProvider(keysize))
            {
                try
                {
                    RSAEncryption.FromXmlString(publicKey.ToString());
                    var encryptedData = RSAEncryption.Encrypt(bytesToEncrypt, true);
                    var base64Encrypted = Convert.ToBase64String(encryptedData);
                    return base64Encrypted;
                }
                finally
                {
                    RSAEncryption.PersistKeyInCsp = false;
                }
            }
        }

        public static string Decrypt(string textToDecrypt, string privateKey, int keysize)
        {
            using (var RSADecrypt = new RSACryptoServiceProvider(keysize))
            {
                try
                {
                    RSADecrypt.FromXmlString(privateKey);

                    var resultBytes = Convert.FromBase64String(textToDecrypt);
                    var decryptedBytes = RSADecrypt.Decrypt(resultBytes, true);
                    var decryptedData = Encoding.UTF8.GetString(decryptedBytes);
                    return decryptedData.ToString();
                }
                finally
                {
                    RSADecrypt.PersistKeyInCsp = false;
                }
            }
        }
    }
}
