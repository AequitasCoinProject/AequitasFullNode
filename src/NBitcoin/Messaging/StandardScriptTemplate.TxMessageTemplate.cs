using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Numerics;
using NBitcoin.Crypto;
using NBitcoin.Messaging;
using Newtonsoft.Json;

namespace NBitcoin
{
    public class WantedSystemMessageTemplate : TxNullDataTemplate
    {
        public WantedSystemMessageTemplate(int maxScriptSize) : base(maxScriptSize)
        {
        }

        private static readonly WantedSystemMessageTemplate _Instance = new WantedSystemMessageTemplate(MAX_MESSAGELENGTH_RELAY);
        public new static WantedSystemMessageTemplate Instance
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

        public Script GenerateScriptPubKey(string message, string messageRecipient, string replyToAddress, string rewardAddress, bool encryptMessage, RsaPublicKey publicKey, RsaPrivateKey privateKey)
        {
            byte[] pushData = null;

            var wsm = new WantedSystemMessage()
            {
                Encryption = (encryptMessage ? MessageEncryption.RSA4096AES256 : MessageEncryption.None),
                Text = message,
                Metadata = new WantedSystemMessageMetadata()
                {
                    CreationTimeUtc = DateTime.UtcNow.ToString(),
                    RecipientAddress = messageRecipient,
                    ReplyToAddress = replyToAddress,
                    RewardAddress = rewardAddress
                }
            };

            if (encryptMessage)
            {
                pushData = GenerateWantedSystemMessagePushData(wsm, publicKey);
            }
            else
            {
                pushData = GenerateWantedSystemMessagePushData(wsm);
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


        private byte[] GenerateWantedSystemMessagePushData(WantedSystemMessage message, RsaPublicKey publicKey = null)
        {
            byte[] encryptionKey = new byte[0];

            string metadata = JsonConvert.SerializeObject(message.Metadata);

            byte[] uncompressedMetadata = System.Text.Encoding.UTF8.GetBytes(metadata);
            byte[] compressedMetadata = GZIPCompressByteArray(uncompressedMetadata);

            byte[] uncompressedMessage = System.Text.Encoding.UTF8.GetBytes(message.Text);
            if (message.Encryption == MessageEncryption.RSA4096AES256)
            {
                byte[] aesKey = GetRandomData(256);

                encryptionKey = RSAEncryptByteArray(aesKey, publicKey);
                byte[] encryptedMessage = AESEncryptByteArray(uncompressedMessage, aesKey);

                uncompressedMessage = encryptedMessage;
            }
            byte[] compressedMessage = GZIPCompressByteArray(uncompressedMessage);

            byte[] header = System.Text.Encoding.UTF8.GetBytes("TWS");
            byte version = (byte)message.Version;
            byte compression = (byte)message.Compression;
            byte checksumType = (byte)message.ChecksumType;
            byte encryptionType = (byte)message.Encryption;
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

        public WantedSystemMessage GetWantedSystemMessage(Script scriptPubKey, RsaPrivateKey privateKey = null)
        {
            var msg = new WantedSystemMessage();

            if (scriptPubKey.Length < 13) throw new Exception("This ScriptPubKey is not a valid Wanted System message.");

            Op[] scriptPubKeyOps = scriptPubKey.ToOps().ToArray();            
            if ((scriptPubKeyOps[0].Code != OpcodeType.OP_NOP) || (scriptPubKeyOps[1].Code != OpcodeType.OP_NOP) || (scriptPubKeyOps[2].Code != OpcodeType.OP_RETURN)) throw new Exception("This ScriptPubKey is not a valid Wanted System message.");

            byte[] pd = scriptPubKeyOps[3].PushData;

            byte[] header = pd.Take<byte>(3).ToArray();
            msg.Version = pd[3];
            if (msg.Version != 1) throw new Exception($"Wanted System message vesion {msg.Version} is not supported.");

            msg.Compression = (MessageCompression)pd[4];
            if (msg.Compression != MessageCompression.GZip) throw new Exception($"Wanted System message compression {msg.Compression} is not supported.");

            msg.ChecksumType = (MessageChecksum)pd[5];
            if (msg.ChecksumType != MessageChecksum.None) throw new Exception($"Wanted System message checksum {msg.ChecksumType} is not supported.");

            msg.Encryption = (MessageEncryption)pd[6];
            if (msg.Encryption != MessageEncryption.RSA4096AES256) throw new Exception($"Wanted System message encryption {msg.Encryption} is not supported.");

            ushort encryptionKeyLength = BitConverter.ToUInt16(pd, 7);
            ushort metadataLength = BitConverter.ToUInt16(pd, 9);
            ushort messageLength = BitConverter.ToUInt16(pd, 11);

            byte[] encryptionKey = new byte[encryptionKeyLength];
            byte[] compressedMetadata = new byte[metadataLength];
            byte[] compressedMessage = new byte[messageLength];

            Array.Copy(pd, 13, encryptionKey, 0, encryptionKeyLength);
            Array.Copy(pd, 13 + encryptionKeyLength, compressedMetadata, 0, metadataLength);
            Array.Copy(pd, 13 + encryptionKeyLength + metadataLength, compressedMessage, 0, messageLength);         

            byte[] uncompressedMetadata = GZIPDecompressByteArray(compressedMetadata);
            byte[] uncompressedMessage = GZIPDecompressByteArray(compressedMessage);

            // process metadata using json serializer
            string metadata = System.Text.Encoding.UTF8.GetString(uncompressedMetadata);
            msg.Metadata = JsonConvert.DeserializeObject<WantedSystemMessageMetadata>(metadata);

            // Decrypt the message if needed
            if (msg.Encryption == MessageEncryption.RSA4096AES256)
            {
                if (privateKey == null) throw new Exception("The message is encrypted but the decryption key was not provided.");

                byte[] aesKey = null;
                try
                {
                    aesKey = RSADecryptByteArray(encryptionKey, privateKey);
                }
                catch
                {
                    throw new Exception("The private key you provided isn't a match for the public key the message was encrypted with.");
                }

                uncompressedMessage = AESDecryptByteArray(uncompressedMessage, aesKey);
            }
            msg.Text = System.Text.Encoding.UTF8.GetString(uncompressedMessage);

            return msg;
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

        private static byte[] RSAEncryptByteArray(byte[] plaintext, RsaPublicKey publicKey)
        {
            byte[] result = null;
            using (var rsa = RSA.Create())
            {
                RSAParameters rsaParameters = new RSAParameters();
                rsaParameters.Exponent = publicKey.Exponent;
                rsaParameters.Modulus = publicKey.Modulus;
                rsa.ImportParameters(rsaParameters);

                if (plaintext.Count() > publicKey.Modulus.Length - 11)
                {
                    throw new Exception("The RSA message must be shorter than the length of the public key.");
                }

                result = rsa.Encrypt(plaintext, RSAEncryptionPadding.Pkcs1);
            }

            return result;
        }

        private static byte[] RSADecryptByteArray(byte[] ciphertext, RsaPrivateKey privateKey)
        {
            byte[] result = null;
            using (var rsa = RSA.Create())
            {
                RSAParameters rsaParameters = new RSAParameters();
                rsaParameters.D = privateKey.Exponent;
                rsaParameters.DP = privateKey.DP;
                rsaParameters.DQ = privateKey.DQ;
                rsaParameters.Exponent = privateKey.PublicExponent;
                rsaParameters.InverseQ = privateKey.QInv;
                rsaParameters.Modulus = privateKey.Modulus;
                rsaParameters.P = privateKey.P;
                rsaParameters.Q = privateKey.Q;
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
                using (AesManaged cryptor = new AesManaged())
                {
                    cryptor.Mode = CipherMode.CBC;
                    cryptor.Padding = PaddingMode.PKCS7;
                    cryptor.KeySize = 256;
                    cryptor.BlockSize = 128;

                    // we use the random iv created by AesManaged
                    byte[] iv = cryptor.IV;

                    using (CryptoStream cs = new CryptoStream(ms, cryptor.CreateEncryptor(key, iv), CryptoStreamMode.Write))
                    {
                        cs.Write(plaintext, 0, plaintext.Length);
                    }
                    byte[] encryptedContent = ms.ToArray();

                    // create new a byte array that should contain both unencrypted iv and encrypted data
                    byte[] result = new byte[iv.Length + encryptedContent.Length];

                    // copy our 2 array into one
                    System.Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
                    System.Buffer.BlockCopy(encryptedContent, 0, result, iv.Length, encryptedContent.Length);

                    return result;
                }
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
            byte[] iv = new byte[16]; // initial vector is 16 bytes (128 bits, must match the block size)
            byte[] encryptedContent = new byte[ciphertext.Length - iv.Length]; // ciphertest starts with the iv, then the rest should be the encrypted content

            //Copy data to byte array
            System.Buffer.BlockCopy(ciphertext, 0, iv, 0, iv.Length);
            System.Buffer.BlockCopy(ciphertext, iv.Length, encryptedContent, 0, encryptedContent.Length);

            using (MemoryStream ms = new MemoryStream())
            {
                using (AesManaged cryptor = new AesManaged())
                {
                    cryptor.Mode = CipherMode.CBC;
                    cryptor.Padding = PaddingMode.PKCS7;
                    cryptor.KeySize = 256;
                    cryptor.BlockSize = 128;

                    using (CryptoStream cs = new CryptoStream(ms, cryptor.CreateDecryptor(key, iv), CryptoStreamMode.Write))
                    {
                        cs.Write(encryptedContent, 0, encryptedContent.Length);

                    }
                    return ms.ToArray();
                }
            }
        }
    }
}
