using System;
using System.Text;

using OpenSSL.Crypto;

namespace Craswell.Encryption
{
    /// <summary>
    /// Aes encryption tool.
    /// </summary>
    public class AesEncryptionTool
    {
        /// <summary>
        /// The random.
        /// </summary>
        private static Random random = new Random();

        /// <summary>
        /// The length of the salt used in encryption.
        /// </summary>
        private const string SaltDelimiter = "********";

        /// <summary>
        /// The number of iterations for key derivation.
        /// </summary>
        private const int Iterations = 1000;

        /// <summary>
        /// The text encoding type used for the data being encrypted.
        /// </summary>
        private readonly Encoding encoding = Encoding.Unicode;

        /// <summary>
        /// Encrypts the text.
        /// </summary>
        /// <returns>The resulting ciphertext.</returns>
        /// <param name="text">The text to encrypt.</param>
        /// <param name="passphrase">The passphrase used to encrypt the text.</param>
        public string EncryptText(string text, string passphrase)
        {
            string salt = GenerateSalt();
            byte[] saltBytes = encoding.GetBytes(salt);

            byte[] textBytes = encoding.GetBytes(text);
            byte[] passphraseBytes = encoding.GetBytes(passphrase);

            byte[] toEncrypt = new byte[saltBytes.Length + textBytes.Length];
            Buffer.BlockCopy(
                saltBytes,
                0,
                toEncrypt,
                0,
                saltBytes.Length);
            Buffer.BlockCopy(textBytes, 0, toEncrypt, saltBytes.Length, textBytes.Length);

            return this.Encrypt(salt, toEncrypt, passphraseBytes);
        }

        /// <summary>
        /// Decrypts the text.
        /// </summary>
        /// <returns>The resulting plaintext.</returns>
        /// <param name="ciphertext">The ciphertext to decrypt.</param>
        /// <param name="passphrase">The passphrase used to decrypt the text.</param>
        public string DecryptText(string ciphertext, string passphrase)
        {
            string salt = ciphertext.Substring(0, ciphertext.IndexOf(SaltDelimiter) + SaltDelimiter.Length);
            string encryptedText = ciphertext.Replace(salt, string.Empty);

            salt = salt.Replace(SaltDelimiter, string.Empty);
            byte[] passphraseBytes = this.encoding.GetBytes(passphrase);
            byte[] encryptedBytes = Convert.FromBase64String(encryptedText);

            return this.Decrypt(salt, encryptedBytes, passphraseBytes);
        }

        /// <summary>
        /// Generates a salt for encrypting data.
        /// </summary>
        /// <returns>The salt.</returns>
        private static string GenerateSalt()
        {
            byte[] saltBytes = BitConverter.GetBytes(
                DateTime.UtcNow.AddSeconds(random.Next()).Ticks);

            return Convert.ToBase64String(saltBytes);
        }

        /// <summary>
        /// Encrypt the specified data using the salt, data and passphraseBytes.
        /// </summary>
        /// <param name="salt">The salt.</param>
        /// <param name="data">The data to encrypt.</param>
        /// <param name="passphraseBytes">The passphrase bytes.</param>
        /// <returns>The resulting ciphertext from the encryption process.</returns>
        private string Encrypt(string salt, byte[] data, byte[] passphraseBytes)
        {
            using (CipherContext cc = new CipherContext(Cipher.AES_256_CBC))
            {
                byte[] iv;
                byte[] encryptionKey = cc.BytesToKey(
                    MessageDigest.SHA512,
                    encoding.GetBytes(salt),
                    passphraseBytes,
                    Iterations,
                    out iv);

                byte[] ciphertextBytes = cc.Encrypt(
                    data,
                    encryptionKey,
                    iv);

                return string.Concat(
                    salt,
                    SaltDelimiter,
                    Convert.ToBase64String(ciphertextBytes));
            }
        }

        /// <summary>
        /// Decrypt the specified data using salt, saltBytes, and passphraseBytes.
        /// </summary>
        /// <param name="salt">The salt.</param>
        /// <param name="data">The data to decrypt.</param>
        /// <param name="passphraseBytes">The passphrase bytes.</param>
        /// <returns>The plain text after decryption.</returns>
        private string Decrypt(string salt, byte[] data, byte[] passphraseBytes)
        {
            using (CipherContext cc = new CipherContext(Cipher.AES_256_CBC))
            {
                byte[] iv;
                byte[] encryptionKey = cc.BytesToKey(
                    MessageDigest.SHA512,
                    encoding.GetBytes(salt),
                    passphraseBytes,
                    Iterations,
                    out iv);

                byte[] decryptedBytes = cc.Decrypt(data, encryptionKey, iv);
                string decryptedText = encoding.GetString(decryptedBytes);

                return decryptedText.Replace(salt, string.Empty);
            }
        }
    }
}

