using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CryptoPrivacy
{
    public class AESAlgorithms
    {
        private static byte[] TheAESEncryptionBaby(byte[] bytesToBeEncrypted, byte[] passwordBytes)
        {
            byte[] encryptedBytes = null;

            byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9 };

            using (MemoryStream ms = new MemoryStream())
            {
                using (AesCryptoServiceProvider AES = new AesCryptoServiceProvider())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;
                    var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);
                    AES.Mode = CipherMode.CBC;

                    using (var cs = new CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                        cs.Close();
                    }
                    encryptedBytes = ms.ToArray();
                }
            }

            return encryptedBytes;
        }

        public void DecryptFile(string theEncryptedFile, string passwordfromtextbox)
        {

            byte[] bytesToBeDecrypted = File.ReadAllBytes(theEncryptedFile);
            byte[] passwordBytes = Encoding.UTF8.GetBytes(passwordfromtextbox);
            passwordBytes = SHA256.Create().ComputeHash(passwordBytes);

            byte[] bytesDecrypted = AESDecryption(bytesToBeDecrypted, passwordBytes);

            string file = theEncryptedFile;
            File.WriteAllBytes(file, bytesDecrypted);
        }

        private static byte[] AESDecryption(byte[] bytesToBeDecrypted, byte[] passwordBytes)
        {
            byte[] decryptedBytes = null;

            byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9 };

            using (MemoryStream ms = new MemoryStream())
            {
                using (AesCryptoServiceProvider AES = new AesCryptoServiceProvider())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;
                    var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);
                    AES.Mode = CipherMode.CBC;

                    using (var cs = new CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                        cs.Close();
                    }
                    decryptedBytes = ms.ToArray();
                }
            }

            return decryptedBytes;
        }

        public string AesTextDecryption(string DataToDecrypt, string KeyToDecryptWith, string IVKeyToDecryptWith)
        {
            byte[] data = Convert.FromBase64String(DataToDecrypt);
            using (SHA256CryptoServiceProvider SHA256 = new SHA256CryptoServiceProvider())
            {
                byte[] keys = SHA256.ComputeHash(UTF8Encoding.UTF8.GetBytes(KeyToDecryptWith));
                using (AesCryptoServiceProvider AES = new AesCryptoServiceProvider() { Key = keys, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 })
                {
                    string initVector = IVKeyToDecryptWith;
                    byte[] initVectorBytes = Encoding.ASCII.GetBytes(initVector);
                    AES.IV = initVectorBytes;
                    ICryptoTransform transform = AES.CreateDecryptor();
                    byte[] results = transform.TransformFinalBlock(data, 0, data.Length);
                    string Result = UTF8Encoding.UTF8.GetString(results);
                    return Result;
                }
            }
        }

        public void EncryptFile(string file, string password)
        {

            byte[] bytesToBeEncrypted = File.ReadAllBytes(file);
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

            passwordBytes = SHA256.Create().ComputeHash(passwordBytes);

            byte[] bytesEncrypted = TheAESEncryptionBaby(bytesToBeEncrypted, passwordBytes);

            string fileEncrypted = file;

            File.WriteAllBytes(fileEncrypted, bytesEncrypted);
        }

        public string AesTextEncryption(string DataToEncrypt, string KeyToEncryptWith, string IVKey)
        {
            byte[] data = UTF8Encoding.UTF8.GetBytes(DataToEncrypt);
            using (SHA256CryptoServiceProvider SHA256 = new SHA256CryptoServiceProvider())
            {
                string initVector = IVKey;
                byte[] initVectorBytes = Encoding.ASCII.GetBytes(initVector);
                byte[] keys = SHA256.ComputeHash(UTF8Encoding.UTF8.GetBytes(KeyToEncryptWith));
                using (AesCryptoServiceProvider AES = new AesCryptoServiceProvider() { Key = keys, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 })
                {
                    AES.IV = initVectorBytes;
                    ICryptoTransform transform = AES.CreateEncryptor();
                    byte[] results = transform.TransformFinalBlock(data, 0, data.Length);
                    string Result = Convert.ToBase64String(results, 0, results.Length);
                    return Result;
                }
            }
        }
    }
}