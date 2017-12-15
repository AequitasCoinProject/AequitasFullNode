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
            string metadata = "{\"compression\": \"gzip\", \"encryption\": \"" + messageEncryption.ToString() +"\", \"reward-address\": \"\", signature-type: \"ECDSA\", \"message-hash\": \"\", \"message-signature\": \"\", \"reply-to-tx\": \"\"}";
            byte[] uncompressedMetadata = System.Text.Encoding.UTF8.GetBytes(metadata);
            byte[] compressedMetadata = CompressByteArray(uncompressedMetadata);

            byte[] uncompressedMessage = System.Text.Encoding.UTF8.GetBytes(message);
            if (messageEncryption == MessageEncryption.RSA4096AES256)
            {
                byte[] encryptedMessage = EncryptByteArray(uncompressedMessage, publicKeyExponent, publicKeyModulus);
                byte[] decryptedMessage = DecryptByteArray(encryptedMessage, privateKeyDP, privateKeyDQ, privateKeyExponent, privateKeyModulus, privateKeyP, privateKeyPublicExponent, privateKeyQ, privateKeyQInv);

                uncompressedMessage = encryptedMessage;
            }
            byte[] compressedMessage = CompressByteArray(uncompressedMessage);

            byte[] header = System.Text.Encoding.UTF8.GetBytes("TWS");
            byte version = 1;
            byte compression = 1;
            byte checksumType = 0;
            ushort metadataLength = (ushort)compressedMetadata.Length;
            ushort messageLength = (ushort)compressedMessage.Length;

            List<byte> pushDataList = new List<byte>();
            pushDataList.AddRange(header);
            pushDataList.Add(version);
            pushDataList.Add(compression);
            pushDataList.Add(checksumType);
            pushDataList.AddRange(BitConverter.GetBytes(metadataLength));
            pushDataList.AddRange(BitConverter.GetBytes(messageLength));
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

            byte[] uncompressedMetadata = DecompressByteArray(compressedMetadata);
            byte[] uncompressedMessage = DecompressByteArray(compressedMessage);

            return System.Text.Encoding.UTF8.GetString(uncompressedMessage);
        }

        private static byte[] CompressByteArray(byte[] uncompressed)
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

        private static byte[] DecompressByteArray(byte[] compressed)
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

        private static byte[] EncryptByteArray(byte[] plaintext, byte[] publicKeyExponent, byte[] publicKeyModulus)
        {
            //byte[] publicKey1024bit = {214,46,220,83,160,73,40,39,201,155,19,202,3,11,191,178,56,
            //                           74,90,36,248,103,18,144,170,163,145,87,54,61,34,220,222,
            //                           207,137,149,173,14,92,120,206,222,158,28,40,24,30,16,175,
            //                           108,128,35,230,118,40,121,113,125,216,130,11,24,90,48,194,
            //                           240,105,44,76,34,57,249,228,125,80,38,9,136,29,117,207,139,
            //                           168,181,85,137,126,10,126,242,120,247,121,8,100,12,201,171,
            //                           38,226,193,180,190,117,177,87,143,242,213,11,44,180,113,93,
            //                           106,99,179,68,175,211,164,116,64,148,226,254,172,147};

            //byte[] publicKey512bit  = {214,46,220,83,160,73,40,39,201,155,19,202,3,11,191,178,56,
            //                           168,181,85,137,126,10,126,242,120,247,121,8,100,12,201,171,
            //                           38,226,193,180,190,117,177,87,143,242,213,11,44,180,113,93,
            //                           106,99,179,68,175,211,164,116,64,148,226,254,172,147,99};

            //byte[] publicKey256bit =  {214,46,220,83,160,73,40,39,201,155,19,202,3,11,191,178,56,
            //                            106,99,179,68,175,211,164,116,64,148,226,254,172,147,88};

            //byte[] publicKey = HexadecimalStringToByteArray(recipientPublicKey);

            //Cryptograph crypto = new Cryptograph();
            //RSAParameters[] keys = crypto.GenarateRSAKeyPairs();

            //BitcoinSecret bs = key.GetWif(Network.StratisTest);
            //byte[] secretBytes = bs.ToBytes();


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

        private static byte[] DecryptByteArray(byte[] ciphertext, byte[] privateKeyDP, byte[] privateKeyDQ, byte[] privateKeyExponent, byte[] privateKeyModulus, byte[] privateKeyP, byte[] privateKeyPublicExponent, byte[] privateKeyQ, byte[] privateKeyQInv)
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

        /* The default .NET Framework implementation doesn't support .NET Core */

        /*
                /// <summary>
                /// Encrypt a byte array using AES 128
                /// </summary>
                /// <param name="key">128 bit key</param>
                /// <param name="secret">byte array that need to be encrypted</param>
                /// <returns>Encrypted array</returns>
                private static byte[] EncryptByteArray(byte[] key, byte[] secret)
                {
                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (AesManaged cryptor = new AesManaged())
                        {
                            cryptor.Mode = CipherMode.CBC;
                            cryptor.Padding = PaddingMode.PKCS7;
                            cryptor.KeySize = 128;
                            cryptor.BlockSize = 128;

                            //We use the random generated iv created by AesManaged
                            byte[] iv = cryptor.IV;

                            using (CryptoStream cs = new CryptoStream(ms, cryptor.CreateEncryptor(key, iv), CryptoStreamMode.Write))
                            {
                                cs.Write(secret, 0, secret.Length);
                            }
                            byte[] encryptedContent = ms.ToArray();

                            //Create new byte array that should contain both unencrypted iv and encrypted data
                            byte[] result = new byte[iv.Length + encryptedContent.Length];

                            //copy our 2 array into one
                            System.Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
                            System.Buffer.BlockCopy(encryptedContent, 0, result, iv.Length, encryptedContent.Length);

                            return result;
                        }
                    }
                }

                /// <summary>
                /// Decrypt a byte array using AES 128
                /// </summary>
                /// <param name="key">key in bytes</param>
                /// <param name="secret">the encrypted bytes</param>
                /// <returns>decrypted bytes</returns>
                private static byte[] DecryptByteArray(byte[] key, byte[] secret)
                {
                    byte[] iv = new byte[16]; //initial vector is 16 bytes
                    byte[] encryptedContent = new byte[secret.Length - 16]; //the rest should be encryptedcontent

                    //Copy data to byte array
                    System.Buffer.BlockCopy(secret, 0, iv, 0, iv.Length);
                    System.Buffer.BlockCopy(secret, iv.Length, encryptedContent, 0, encryptedContent.Length);

                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (AesManaged cryptor = new AesManaged())
                        {
                            cryptor.Mode = CipherMode.CBC;
                            cryptor.Padding = PaddingMode.PKCS7;
                            cryptor.KeySize = 128;
                            cryptor.BlockSize = 128;

                            using (CryptoStream cs = new CryptoStream(ms, cryptor.CreateDecryptor(key, iv), CryptoStreamMode.Write))
                            {
                                cs.Write(encryptedContent, 0, encryptedContent.Length);

                            }
                            return ms.ToArray();
                        }
                    }
                }
        */
    }
}
