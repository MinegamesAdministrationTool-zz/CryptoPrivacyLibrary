using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CryptoPrivacy
{
    public class HashingAlgorithms
    {
        public static string HashingMD5(string TextToHash)
        {
            using (MD5CryptoServiceProvider MD5 = new MD5CryptoServiceProvider())
            {
                byte[] keys = MD5.ComputeHash(UTF8Encoding.UTF8.GetBytes(TextToHash));
                StringBuilder builder = new StringBuilder();
                for (int i = 0; i < keys.Length; i++)
                {
                    builder.Append(keys[i].ToString("x2"));
                }
                string FinalHash = builder.ToString();
                return FinalHash;
            }
        }

        public static string HashingSHA1(string TextToHash)
        {
            using (SHA1CryptoServiceProvider SHA1 = new SHA1CryptoServiceProvider())
            {
                byte[] keys = SHA1.ComputeHash(UTF8Encoding.UTF8.GetBytes(TextToHash));
                StringBuilder builder = new StringBuilder();
                for (int i = 0; i < keys.Length; i++)
                {
                    builder.Append(keys[i].ToString("x2"));
                }
                string FinalHash = builder.ToString();
                return FinalHash;
            }
        }

        public static string HashingSHA256(string TextToHash)
        {
            using (SHA256CryptoServiceProvider SHA256 = new SHA256CryptoServiceProvider())
            {
                byte[] keys = SHA256.ComputeHash(UTF8Encoding.UTF8.GetBytes(TextToHash));
                StringBuilder builder = new StringBuilder();
                for (int i = 0; i < keys.Length; i++)
                {
                    builder.Append(keys[i].ToString("x2"));
                }
                string FinalHash = builder.ToString();
                return FinalHash;
            }
        }

        public static string HashingSHA384(string TextToHash)
        {
            using (SHA384CryptoServiceProvider SHA384 = new SHA384CryptoServiceProvider())
            {
                byte[] keys = SHA384.ComputeHash(UTF8Encoding.UTF8.GetBytes(TextToHash));
                StringBuilder builder = new StringBuilder();
                for (int i = 0; i < keys.Length; i++)
                {
                    builder.Append(keys[i].ToString("x2"));
                }
                string FinalHash = builder.ToString();
                return FinalHash;
            }
        }

        public static string HashingSHA512(string TextToHash)
        {
            using (SHA512CryptoServiceProvider SHA512 = new SHA512CryptoServiceProvider())
            {
                byte[] keys = SHA512.ComputeHash(UTF8Encoding.UTF8.GetBytes(TextToHash));
                StringBuilder builder = new StringBuilder();
                for (int i = 0; i < keys.Length; i++)
                {
                    builder.Append(keys[i].ToString("x2"));
                }
                string FinalHash = builder.ToString();
                return FinalHash;
            }
        }

        public static string FileHashingSHA512(string FilePath)
        {
            FileStream GetFileToHash = new FileStream(FilePath, FileMode.Open);
            SHA512CryptoServiceProvider SHA512 = new SHA512CryptoServiceProvider();
            byte[] Hash = SHA512.ComputeHash(GetFileToHash);
            string FinalHash = BitConverter.ToString(Hash).Replace("-", string.Empty).ToLower();
            GetFileToHash.Close();
            return FinalHash;
        }

        public static string FileHashingSHA384(string FilePath)
        {
            FileStream GetFileToHash = new FileStream(FilePath, FileMode.Open);
            SHA384CryptoServiceProvider SHA384 = new SHA384CryptoServiceProvider();
            byte[] Hash = SHA384.ComputeHash(GetFileToHash);
            string FinalHash = BitConverter.ToString(Hash).Replace("-", string.Empty).ToLower();
            GetFileToHash.Close();
            return FinalHash;
        }

        public static string FileHashingSHA256(string FilePath)
        {
            FileStream GetFileToHash = new FileStream(FilePath, FileMode.Open);
            SHA256CryptoServiceProvider SHA256 = new SHA256CryptoServiceProvider();
            byte[] Hash = SHA256.ComputeHash(GetFileToHash);
            string FinalHash = BitConverter.ToString(Hash).Replace("-", string.Empty).ToLower();
            GetFileToHash.Close();
            return FinalHash;
        }

        public static string FileHashingSHA1(string FilePath)
        {
            FileStream GetFileToHash = new FileStream(FilePath, FileMode.Open);
            SHA1CryptoServiceProvider SHA1 = new SHA1CryptoServiceProvider();
            byte[] Hash = SHA1.ComputeHash(GetFileToHash);
            string FinalHash = BitConverter.ToString(Hash).Replace("-", string.Empty).ToLower();
            GetFileToHash.Close();
            return FinalHash;
        }

        public static string FileHashingMD5(string FilePath)
        {
            FileStream GetFileToHash = new FileStream(FilePath, FileMode.Open);
            MD5CryptoServiceProvider MD5 = new MD5CryptoServiceProvider();
            byte[] Hash = MD5.ComputeHash(GetFileToHash);
            string FinalHash = BitConverter.ToString(Hash).Replace("-", string.Empty).ToLower();
            GetFileToHash.Close();
            return FinalHash;
        }

        public static string HashingHMACMD5(string TextToHash, string Key)
        {
            string KeyToHashWith = Key;
            byte[] KeyToHash = Encoding.ASCII.GetBytes(KeyToHashWith);
            HMACMD5 MD5Hashing = new HMACMD5();
            MD5Hashing.Key = KeyToHash;
            var TheHash = MD5Hashing.ComputeHash(UTF8Encoding.UTF8.GetBytes(TextToHash));
            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < TheHash.Length; i++)
            {
                builder.Append(TheHash[i].ToString("x2"));
            }
            string FinalHash = builder.ToString();
            return FinalHash;
        }

        public static string HashingHMACSHA1(string TextToHash, string Key)
        {
            string KeyToHashWith = Key;
            byte[] KeyToHash = Encoding.ASCII.GetBytes(KeyToHashWith);
            HMACSHA1 SHA1Hashing = new HMACSHA1();
            SHA1Hashing.Key = KeyToHash;
            var TheHash = SHA1Hashing.ComputeHash(UTF8Encoding.UTF8.GetBytes(TextToHash));
            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < TheHash.Length; i++)
            {
                builder.Append(TheHash[i].ToString("x2"));
            }
            string FinalHash = builder.ToString();
            return FinalHash;
        }

        public string HashingHMACSHA256(string TextToHash, string Key)
        {
            string KeyToHashWith = Key;
            byte[] KeyToHash = Encoding.ASCII.GetBytes(KeyToHashWith);
            HMACSHA256 SHA256Hashing = new HMACSHA256();
            SHA256Hashing.Key = KeyToHash;
            var TheHash = SHA256Hashing.ComputeHash(UTF8Encoding.UTF8.GetBytes(TextToHash));
            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < TheHash.Length; i++)
            {
                builder.Append(TheHash[i].ToString("x2"));
            }
            string FinalHash = builder.ToString();
            return FinalHash;
        }

        public static string HashingHMACSHA384(string TextToHash, string Key)
        {
            string KeyToHashWith = Key;
            byte[] KeyToHash = Encoding.ASCII.GetBytes(KeyToHashWith);
            HMACSHA384 SHA384Hashing = new HMACSHA384();
            SHA384Hashing.Key = KeyToHash;
            var TheHash = SHA384Hashing.ComputeHash(UTF8Encoding.UTF8.GetBytes(TextToHash));
            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < TheHash.Length; i++)
            {
                builder.Append(TheHash[i].ToString("x2"));
            }
            string FinalHash = builder.ToString();
            return FinalHash;
        }

        public static string HashingHMACSHA512(string TextToHash, string Key)
        {
            string KeyToHashWith = Key;
            byte[] KeyToHash = Encoding.ASCII.GetBytes(KeyToHashWith);
            HMACSHA512 SHA512Hashing = new HMACSHA512();
            SHA512Hashing.Key = KeyToHash;
            var TheHash = SHA512Hashing.ComputeHash(UTF8Encoding.UTF8.GetBytes(TextToHash));
            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < TheHash.Length; i++)
            {
                builder.Append(TheHash[i].ToString("x2"));
            }
            string FinalHash = builder.ToString();
            return FinalHash;
        }
    }
}
