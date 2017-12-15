using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Numerics;

namespace NBitcoin
{
    public enum MessageEncryption { None, RSA4096AES256 }

    public class TxMessageTemplate : TxNullDataTemplate
    {
        public TxMessageTemplate(int maxScriptSize) : base(maxScriptSize)
        {
        }

        private static readonly TxMessageTemplate _Instance = new TxMessageTemplate(MAX_MESSAGELENGTH_RELAY);
        public new static TxMessageTemplate Instance
        {
            get
            {
                return _Instance;
            }
        }

        protected override bool FastCheckScriptPubKey(Script scriptPubKey, out bool needMoreCheck)
        {
            var bytes = scriptPubKey.ToBytes(true);
            if (bytes.Length < 3 ||
                bytes[0] != (byte)OpcodeType.OP_NOP ||
                bytes[1] != (byte)OpcodeType.OP_NOP ||
                bytes[2] != (byte)OpcodeType.OP_RETURN ||
                bytes.Length > this.MaxScriptSizeLimit)
            {
                needMoreCheck = false;
                return false;
            }
            needMoreCheck = false;
            return true;
        }

        public const int MAX_MESSAGELENGTH_RELAY = 3 + 2 + 16 * 1024; //! bytes (+3 for OP_NOP OP_NOP OP_RETURN, +2 for the pushdata opcodes)

        public Script GenerateScriptPubKey(string message, bool encryptMessage, byte[] publicKeyExponent, byte[] publicKeyModulus,
            byte[] privateKeyDP, byte[] privateKeyDQ, byte[] privateKeyExponent, byte[] privateKeyModulus, byte[] privateKeyP, byte[] privateKeyPublicExponent, byte[] privateKeyQ, byte[] privateKeyQInv)
        {
            byte[] pushData = null;
            if (encryptMessage)
            {
                pushData = GenerateTipMessagePushData(message, MessageEncryption.RSA4096AES256, publicKeyExponent, publicKeyModulus, privateKeyDP, privateKeyDQ, privateKeyExponent, privateKeyModulus, privateKeyP, privateKeyPublicExponent, privateKeyQ, privateKeyQInv);
            }
            else
            {
                pushData = GenerateTipMessagePushData(message, MessageEncryption.None);
            }

            return GenerateScriptPubKey(pushData);
        }

        public new Script GenerateScriptPubKey(params byte[][] data)
        {
            if (data == null)
                throw new ArgumentNullException("data");
            Op[] ops = new Op[data.Length + 3];
            ops[0] = OpcodeType.OP_NOP;
            ops[1] = OpcodeType.OP_NOP;
            ops[2] = OpcodeType.OP_RETURN;
            for (int i = 0; i < data.Length; i++)
            {
                ops[3 + i] = Op.GetPushOp(data[i]);
            }
            var script = new Script(ops);
            if (script.ToBytes(true).Length > this.MaxScriptSizeLimit)
                throw new ArgumentOutOfRangeException("data", "Data in the Message transaction should have a maximum size of " + this.MaxScriptSizeLimit + " bytes");
            return script;
        }

        public override TxOutType Type
        {
            get
            {
                return TxOutType.TX_MESSAGE;
            }
        }


        private byte[] GenerateTipMessagePushData(string message, MessageEncryption messageEncryption, byte[] publicKeyExponent = null, byte[] publicKeyModulus = null,
            byte[] privateKeyDP = null, byte[] privateKeyDQ = null, byte[] privateKeyExponent = null, byte[] privateKeyModulus = null, byte[] privateKeyP = null, byte[] privateKeyPublicExponent = null, byte[] privateKeyQ = null, byte[] privateKeyQInv = null)
        {
            byte[] encryptionKey = new byte[0];

            string metadata = "{\"compression\": \"gzip\", \"encryption\": \"" + messageEncryption.ToString() + "\", \"reward-address\": \"\", signature-type: \"ECDSA\", \"message-hash\": \"\", \"message-signature\": \"\", \"reply-to-tx\": \"\"}";
            byte[] uncompressedMetadata = System.Text.Encoding.UTF8.GetBytes(metadata);
            byte[] compressedMetadata = GZIPCompressByteArray(uncompressedMetadata);

            byte[] uncompressedMessage = System.Text.Encoding.UTF8.GetBytes(message);
            if (messageEncryption == MessageEncryption.RSA4096AES256)
            {
                byte[] aesKey = GetRandomData(256);

                encryptionKey = RSAEncryptByteArray(aesKey, publicKeyExponent, publicKeyModulus);
                //byte[] decryptedKey = RSADecryptByteArray(encryptionKey, privateKeyDP, privateKeyDQ, privateKeyExponent, privateKeyModulus, privateKeyP, privateKeyPublicExponent, privateKeyQ, privateKeyQInv);

                byte[] encryptedMessage = AESEncryptByteArray(uncompressedMessage, aesKey);
                //byte[] decryptedMessage = AESDecryptByteArray(encryptedMessage, aesKey);

                uncompressedMessage = encryptedMessage;
            }
            byte[] compressedMessage = GZIPCompressByteArray(uncompressedMessage);

            byte[] header = System.Text.Encoding.UTF8.GetBytes("TWS");
            byte version = 1;
            byte compression = 1;
            byte checksumType = 0;
            byte encryptionType = messageEncryption == MessageEncryption.RSA4096AES256 ? (byte)1 : (byte)0;
            ushort encryptionKeyLength = (ushort)encryptionKey.Length;
            ushort metadataLength = (ushort)compressedMetadata.Length;
            ushort messageLength = (ushort)compressedMessage.Length;

            List<byte> pushDataList = new List<byte>();
            pushDataList.AddRange(header);
            pushDataList.Add(version);
            pushDataList.Add(compression);
            pushDataList.Add(checksumType);
            pushDataList.Add(encryptionType);
            pushDataList.AddRange(BitConverter.GetBytes(encryptionKeyLength));
            pushDataList.AddRange(BitConverter.GetBytes(metadataLength));
            pushDataList.AddRange(BitConverter.GetBytes(messageLength));
            pushDataList.AddRange(encryptionKey);
            pushDataList.AddRange(compressedMetadata);
            pushDataList.AddRange(compressedMessage);

            if (pushDataList.Count > 16 * 1024) throw new Exception("Push data can't be bigger than 16 kbytes.");

            return pushDataList.ToArray();
        }

        public string GetMessage(Script scriptPubKey)
        {
            if (scriptPubKey.Length < 13) throw new Exception("This ScriptPubKey is not a valid Wanted System message.");

            byte[] scriptPubKeyBytes = scriptPubKey.ToBytes();
            byte[] nopnopreturn = scriptPubKeyBytes.Take<byte>(3).ToArray();
            ushort pushdataLength = BitConverter.ToUInt16(scriptPubKeyBytes, 3);

            byte[] pushData = new byte[scriptPubKeyBytes.Length - 5];
            Array.Copy(scriptPubKeyBytes, 5, pushData, 0, pushData.Length);

            if ((nopnopreturn[0] != 0x61) || (nopnopreturn[1] != 0x61) || (nopnopreturn[2] != 0x6a)) throw new Exception("This ScriptPubKey is not a valid Wanted System message.");

            byte[] header = pushData.Take<byte>(3).ToArray();
            byte version = pushData[3];
            byte compression = pushData[4];
            byte checksumType = pushData[5];
            ushort metadataLength = BitConverter.ToUInt16(pushData, 6);
            ushort messageLength = BitConverter.ToUInt16(pushData, 8);

            byte[] compressedMetadata = new byte[metadataLength];
            byte[] compressedMessage = new byte[messageLength];

            Array.Copy(pushData, 10, compressedMetadata, 0, metadataLength);
            Array.Copy(pushData, 10 + metadataLength, compressedMessage, 0, messageLength);

            byte[] uncompressedMetadata = GZIPDecompressByteArray(compressedMetadata);
            byte[] uncompressedMessage = GZIPDecompressByteArray(compressedMessage);

            return System.Text.Encoding.UTF8.GetString(uncompressedMessage);
        }

        private static byte[] GZIPCompressByteArray(byte[] uncompressed)
        {
            using (var msi = new MemoryStream(uncompressed))
            using (var mso = new MemoryStream())
            {
                using (var gs = new GZipStream(mso, CompressionLevel.Optimal))
                {
                    msi.CopyTo(gs);
                }
                return mso.ToArray();
            }
        }

        private static byte[] GZIPDecompressByteArray(byte[] compressed)
        {
            using (var msi = new MemoryStream(compressed))
            using (var mso = new MemoryStream())
            {
                using (var gs = new GZipStream(msi, CompressionMode.Decompress))
                {
                    gs.CopyTo(mso);
                }
                return mso.ToArray();
            }
        }

        private static byte[] RSAEncryptByteArray(byte[] plaintext, byte[] publicKeyExponent, byte[] publicKeyModulus)
        {
            byte[] result = null;
            using (var rsa = RSA.Create())
            {
                RSAParameters rsaParameters = new RSAParameters();
                rsaParameters.Exponent = publicKeyExponent;
                rsaParameters.Modulus = publicKeyModulus;
                rsa.ImportParameters(rsaParameters);

                if (plaintext.Count() > publicKeyModulus.Length - 11)
                {
                    throw new Exception("The RSA message must be shorter than the length of the public key.");
                }

                result = rsa.Encrypt(plaintext, RSAEncryptionPadding.Pkcs1);
            }

            return result;
        }

        private static byte[] RSADecryptByteArray(byte[] ciphertext, byte[] privateKeyDP, byte[] privateKeyDQ, byte[] privateKeyExponent, byte[] privateKeyModulus, byte[] privateKeyP, byte[] privateKeyPublicExponent, byte[] privateKeyQ, byte[] privateKeyQInv)
        {
            byte[] result = null;
            using (var rsa = RSA.Create())
            {
                RSAParameters rsaParameters = new RSAParameters();
                rsaParameters.D = privateKeyExponent;
                rsaParameters.DP = privateKeyDP;
                rsaParameters.DQ = privateKeyDQ;
                rsaParameters.Exponent = privateKeyPublicExponent;
                rsaParameters.InverseQ = privateKeyQInv;
                rsaParameters.Modulus = privateKeyModulus;
                rsaParameters.P = privateKeyP;
                rsaParameters.Q = privateKeyQ;
                rsa.ImportParameters(rsaParameters);

                result = rsa.Decrypt(ciphertext, RSAEncryptionPadding.Pkcs1);
            }

            return result;
        }

        private static byte[] GetRandomData(int bits)
        {
            var result = new byte[bits / 8];
            RandomNumberGenerator.Create().GetBytes(result);
            return result;
        }

        public static byte[] HexadecimalStringToByteArray(string hex)
        {
            if (hex.Length % 2 == 1)
                throw new Exception("The binary key cannot have an odd number of digits");

            byte[] arr = new byte[hex.Length >> 1];

            for (int i = 0; i < hex.Length >> 1; ++i)
            {
                arr[i] = (byte)((GetHexVal(hex[i << 1]) << 4) + (GetHexVal(hex[(i << 1) + 1])));
            }

            return arr;
        }

        public static int GetHexVal(char hex)
        {
            int val = (int)hex;
            return val - (val < 58 ? 48 : (val < 97 ? 55 : 87));
        }

        /* The default .NET Framework implementation doesn't support .NET Core 1.1 */

        /// <summary>
        /// Encrypt a byte array using AES 256
        /// </summary>
        /// <param name="plaintext">byte array that need to be encrypted</param>
        /// <param name="key">128 bit key</param>
        /// <returns>Encrypted array</returns>
        private static byte[] AESEncryptByteArray(byte[] plaintext, byte[] key)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                //using (AesManaged cryptor = new AesManaged())
                //{
                //    cryptor.Mode = CipherMode.CBC;
                //    cryptor.Padding = PaddingMode.PKCS7;
                //    cryptor.KeySize = 256;
                //    cryptor.BlockSize = 256;

                //    //We use the random generated iv created by AesManaged
                //    byte[] iv = cryptor.IV;

                //    using (CryptoStream cs = new CryptoStream(ms, cryptor.CreateEncryptor(key, iv), CryptoStreamMode.Write))
                //    {
                //        cs.Write(plaintext, 0, plaintext.Length);
                //    }
                //    byte[] encryptedContent = ms.ToArray();

                //    //Create new byte array that should contain both unencrypted iv and encrypted data
                //    byte[] result = new byte[iv.Length + encryptedContent.Length];

                //    //copy our 2 array into one
                //    System.Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
                //    System.Buffer.BlockCopy(encryptedContent, 0, result, iv.Length, encryptedContent.Length);

                //    return result;
                //}
                return null;
            }
        }

        /// <summary>
        /// Decrypt a byte array using AES 256
        /// </summary>
        /// <param name="ciphertext">the encrypted bytes</param>
        /// <param name="key">key in bytes</param>
        /// <returns>decrypted bytes</returns>
        private static byte[] AESDecryptByteArray(byte[] ciphertext, byte[] key)
        {
            byte[] iv = new byte[16]; //initial vector is 16 bytes
            byte[] encryptedContent = new byte[ciphertext.Length - 16]; //the rest should be encryptedcontent

            //Copy data to byte array
            System.Buffer.BlockCopy(ciphertext, 0, iv, 0, iv.Length);
            System.Buffer.BlockCopy(ciphertext, iv.Length, encryptedContent, 0, encryptedContent.Length);

            using (MemoryStream ms = new MemoryStream())
            {
                //using (AesManaged cryptor = new AesManaged())
                //{
                //    cryptor.Mode = CipherMode.CBC;
                //    cryptor.Padding = PaddingMode.PKCS7;
                //    cryptor.KeySize = 256;
                //    cryptor.BlockSize = 256;

                //    using (CryptoStream cs = new CryptoStream(ms, cryptor.CreateDecryptor(key, iv), CryptoStreamMode.Write))
                //    {
                //        cs.Write(encryptedContent, 0, encryptedContent.Length);

                //    }
                //    return ms.ToArray();
                //}
                return null;
            }
        }
    }
}
