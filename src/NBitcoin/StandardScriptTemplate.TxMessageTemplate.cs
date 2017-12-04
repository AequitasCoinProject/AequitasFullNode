using NBitcoin.Crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.IO.Compression;

namespace NBitcoin
{
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

        public Script GenerateScriptPubKey(string message)
        {
            return GenerateScriptPubKey(GenerateTipMessagePushData(message));
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


        private byte[] GenerateTipMessagePushData(string message)
        {
            string metadata = "{\"compression\": \"gzip\", \"encryption\": \"none\", \"reward-address\": \"\", signature-type: \"ECDSA\", \"message-hash\": \"\", \"message-signature\": \"\", \"reply-to-tx\": \"\"}";
            byte[] uncompressedMetadata = System.Text.Encoding.UTF8.GetBytes(metadata);
            byte[] compressedMetadata = CompressByteArray(uncompressedMetadata);

            byte[] uncompressedMessage = System.Text.Encoding.UTF8.GetBytes(message);
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
    }
}
