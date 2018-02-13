using DigiWar.Security.Cryptography;
using Flexinets.Core.Database.Models;
using Microsoft.AspNetCore.Identity;
using System;
using System.Security.Cryptography;
using System.Text;

namespace Flexinets.Security
{
    public static class CryptoMethods
    {
        /// <summary>
        /// Generate a random string
        /// </summary>
        /// <param name="length">Length in bytes</param>
        /// <returns></returns>
        public static String GetRandomString(Int32 length)
        {
            using (var rng = new RNGCryptoServiceProvider())
            {
                var randomBytes = new Byte[48];
                rng.GetBytes(randomBytes);

                const String passwordChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
                Int32 passwordLength = length;

                Int32 seed = (randomBytes[0] & 0x7f) << 24 | randomBytes[1] << 16 | randomBytes[2] << 8 | randomBytes[3];
                var random = new Random(seed);

                String salt = "";
                for (Int32 i = 0; i < passwordLength; i++)
                {
                    salt += passwordChars[random.Next(passwordChars.Length)];
                }
                return salt;
            }
        }


        /// <summary>
        /// Validate a password using 3 different available hash algorithms + fallback to plaintext
        /// </summary>
        /// <param name="hash"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public static PasswordVerificationResult VerifyHashedPassword(String hash, String password)
        {
            var hasher = new PasswordHasher<Admins>();
            try
            {
                return hasher.VerifyHashedPassword(null, hash, password);
            }
            catch (FormatException)
            {
                // Ignore format exceptions.. old password hashes...
            }
            if (hash.StartsWith("$1$") && hash == GetCryptMD5Hash(password, hash.Substring(3, 8)))
            {
                return PasswordVerificationResult.SuccessRehashNeeded;
            }
            else if (hash.StartsWith("{MD5}") && hash == "{MD5}" + GetMD5Hash(password))
            {
                return PasswordVerificationResult.SuccessRehashNeeded;
            }
            else if (hash.StartsWith("{crypt}") && hash == "{crypt}" + Crypt(hash.Substring(7, 2), password))
            {
                return PasswordVerificationResult.SuccessRehashNeeded;
            }
            else if (hash == password)
            {
                return PasswordVerificationResult.SuccessRehashNeeded;
            }

            return PasswordVerificationResult.Failed;
        }


        /// <summary>
        /// Hash a password using default algorithm
        /// </summary>
        /// <param name="password"></param>
        /// <returns></returns>
        public static String HashPassword(String password)
        {
            var hasher = new PasswordHasher<Admins>();
            return hasher.HashPassword(null, password);
        }


        /// <summary>
        /// Crypt password hash
        /// </summary>
        /// <param name="salt"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        private static String Crypt(String salt, String password)
        {
            return UnixCrypt.Crypt(salt, password);
        }


        /// <summary>
        /// Gets the MD5 hash of a string
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        private static String GetMD5Hash(String input)
        {
            using (var md5 = MD5.Create())
            {
                byte[] bs = md5.ComputeHash(Encoding.UTF8.GetBytes(input));
                var s = new StringBuilder();
                foreach (var b in bs)
                    s.Append(b.ToString("x2").ToLower());
                return s.ToString();
            }
        }


        /// <summary>
        /// Gets the SHA512 hash of a string
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>        
        public static String GetSHA512Hash(String input)
        {
            using (var hasher = SHA512.Create())
            {
                var bs = hasher.ComputeHash(Encoding.UTF8.GetBytes(input));
                var s = new StringBuilder();
                foreach (var b in bs)
                {
                    s.Append(b.ToString("x2").ToLower());
                }
                return s.ToString();
            }
        }


        /// <summary>
        /// Returns a unix style crypt md5 hash
        /// </summary>
        /// <param name="password"></param>
        /// <param name="salt"></param>
        /// <returns></returns>
        private static String GetCryptMD5Hash(String password, String salt)
        {
            return Unix_MD5Crypt.MD5Crypt.crypt(password, salt);
        }


        /// <summary>
        /// Returns a unix style crypt md5 hash with new random salt
        /// </summary>
        /// <param name="password"></param>
        /// <returns></returns>
        private static String GetCryptMD5Hash(String password)
        {
            return GetCryptMD5Hash(password, GenerateSalt());
        }


        /// <summary>
        /// Generate a random salt
        /// </summary>
        /// <returns>8 byte string</returns>
        private static String GenerateSalt()
        {
            using (var rng = new RNGCryptoServiceProvider())
            {
                var randomBytes = new Byte[48];
                rng.GetBytes(randomBytes);

                const String passwordChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./";
                const Int32 passwordLength = 8;

                Int32 seed = (randomBytes[0] & 0x7f) << 24 | randomBytes[1] << 16 | randomBytes[2] << 8 | randomBytes[3];
                var random = new Random(seed);

                var salt = "";
                for (var i = 0; i < passwordLength; i++)
                {
                    salt += passwordChars[random.Next(passwordChars.Length)];
                }
                return salt;
            }
        }
    }
}
