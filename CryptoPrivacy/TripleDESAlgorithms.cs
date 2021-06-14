using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace CryptoPrivacy
{
    public class TripleDESAlgorithms
    {
        public static string Encrypt(string TextToEncrypt, string Key)
        {
            byte[] data = UTF8Encoding.UTF8.GetBytes(TextToEncrypt);
            using (MD5CryptoServiceProvider MD5 = new MD5CryptoServiceProvider())
            {
                byte[] keys = MD5.ComputeHash(UTF8Encoding.UTF8.GetBytes(Key));
                using (TripleDESCryptoServiceProvider tripDes = new TripleDESCryptoServiceProvider() { Key = keys, Mode = CipherMode.ECB, Padding = PaddingMode.PKCS7 })
                {
                    ICryptoTransform transform = tripDes.CreateEncryptor();
                    byte[] results = transform.TransformFinalBlock(data, 0, data.Length);
                    string FinalResult = Convert.ToBase64String(results, 0, results.Length);
                    return FinalResult;
                }
            }
        }

        public static string Decrypt(string TextToDecrypt, string Key)
        {
            byte[] data = Convert.FromBase64String(TextToDecrypt);
            using (MD5CryptoServiceProvider MD5 = new MD5CryptoServiceProvider())
            {
                byte[] keys = MD5.ComputeHash(UTF8Encoding.UTF8.GetBytes(Key));
                using (TripleDESCryptoServiceProvider DES = new TripleDESCryptoServiceProvider() { Key = keys, Mode = CipherMode.ECB, Padding = PaddingMode.PKCS7 })
                {
                    ICryptoTransform transform = DES.CreateDecryptor();
                    byte[] results = transform.TransformFinalBlock(data, 0, data.Length);
                    string FinalResult = UTF8Encoding.UTF8.GetString(results);
                    return FinalResult;
                }
            }
        }
    }
}
