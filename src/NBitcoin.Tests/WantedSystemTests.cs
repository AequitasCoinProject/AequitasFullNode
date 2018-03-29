using NBitcoin.Crypto;
using NBitcoin.DataEncoders;
using NBitcoin.Protocol;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
#if !NOCONSENSUSLIB
using System.Net.Http;
#endif
using System.Numerics;
using System.Text;
using System.Threading.Tasks;
using Xunit;
using Newtonsoft.Json.Linq;
using System.Runtime.InteropServices;
using System.IO.Compression;
using NBitcoin.BitcoinCore;

namespace NBitcoin.Tests
{
	public class WantedSystemTests
	{
        public WantedSystemTests()
        {
            // These flags may get set due to static network initializers
            // which include the initializers for Stratis.
            Transaction.TimeStamp = false;
            Block.BlockSignature = false;
        }

        static Dictionary<string, OpcodeType> mapOpNames = new Dictionary<string, OpcodeType>();
		public static Script ParseScript(string s)
		{
			MemoryStream result = new MemoryStream();
			if(mapOpNames.Count == 0)
			{
				mapOpNames = new Dictionary<string, OpcodeType>(Op._OpcodeByName);
				foreach(var kv in mapOpNames.ToArray())
				{
					if(kv.Key.StartsWith("OP_", StringComparison.Ordinal))
					{
						var name = kv.Key.Substring(3, kv.Key.Length - 3);
						mapOpNames.AddOrReplace(name, kv.Value);
					}
				}
			}

			var words = s.Split(' ', '\t', '\n');

			foreach(string w in words)
			{
				if(w == "")
					continue;
				if(w.All(l => l.IsDigit()) ||
					(w.StartsWith("-") && w.Substring(1).All(l => l.IsDigit())))
				{

					// Number
					long n = long.Parse(w);
					Op.GetPushOp(n).WriteTo(result);
				}
				else if(w.StartsWith("0x") && HexEncoder.IsWellFormed(w.Substring(2)))
				{
					// Raw hex data, inserted NOT pushed onto stack:
					var raw = Encoders.Hex.DecodeData(w.Substring(2));
					result.Write(raw, 0, raw.Length);
				}
				else if(w.Length >= 2 && w.StartsWith("'") && w.EndsWith("'"))
				{
					// Single-quoted string, pushed as data. NOTE: this is poor-man's
					// parsing, spaces/tabs/newlines in single-quoted strings won't work.
					var b = TestUtils.ToBytes(w.Substring(1, w.Length - 2));
					Op.GetPushOp(b).WriteTo(result);
				}
				else if(mapOpNames.ContainsKey(w))
				{
					// opcode, e.g. OP_ADD or ADD:
					result.WriteByte((byte)mapOpNames[w]);
				}
				else
				{
					Assert.True(false, "Invalid test");
					return null;
				}
			}

			return new Script(result.ToArray());
		}

        [Fact]
        [Trait("UnitTest", "UnitTest")]
        public void CanCompressMessageAsScript()
        {
            var coinsView = new CoinsView();
            Transaction[] dummyTransactions = SetupDummyInputs(coinsView);

            string metadata = "{\"compression\": \"gzip\", \"encryption\": \"none\", \"rewardAddress\": \"\", signatureType: \"ECDSA\", \"messageHash\": \"\", \"messageSignature\": \"\"}";
            byte[] uncompressedMetadata = System.Text.Encoding.UTF8.GetBytes(metadata);
            byte[] compressedMetadata = CompressByteArray(uncompressedMetadata);

            string message = "Bitcoin is a worldwide cryptocurrency and payment system which is the first decentralized digital currency, as the system works without a central repository or single administrator. It was invented by an unknown person or group of people under the name Satoshi Nakamoto and released as open-source software in 2009. The system is peer-to-peer, and transactions take place between users directly, without an intermediary. These transactions are verified by network nodes and recorded in a public distributed ledger called a blockchain. Bitcoins are created as a reward for a process known as mining.They can be exchanged for other currencies, products, and services.As of February 2015, over 100, 000 merchants and vendors accepted bitcoin as payment. Bitcoin can also be held as an investment.According to research produced by Cambridge University in 2017, there are 2.9 to 5.8 million unique users using a cryptocurrency wallet, most of them using bitcoin." + OpcodeType.OP_RETURN;
            byte[] uncompressedMessage = System.Text.Encoding.UTF8.GetBytes(message);
            byte[] compressedMessage = CompressByteArray(uncompressedMessage);

            byte[] header = System.Text.Encoding.UTF8.GetBytes("TWS");
            byte version = 1;
            byte compression = 1;
            byte checksumType = 0;
            ushort metadataLength = (ushort)compressedMetadata.Length;
            ushort messageLength = (ushort)compressedMessage.Length;

            List<byte> pushData = new List<byte>();
            pushData.AddRange(header);
            pushData.Add(version);
            pushData.Add(compression);
            pushData.Add(checksumType);
            pushData.AddRange(BitConverter.GetBytes(metadataLength));
            pushData.AddRange(BitConverter.GetBytes(messageLength));
            pushData.AddRange(compressedMetadata);
            pushData.AddRange(compressedMessage);
            var script = new Script(pushData);

            if (script.Length > 16505) throw new Exception("Push data can't be bigger than 16505 bytes.");

            Transaction t = BuildMessageTransaction(script.ToBytes(), dummyTransactions[0].GetHash());
            coinsView.AddTransaction(dummyTransactions[1], 0);

            AssertCompressed(script, 696);
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

        private Script AssertCompressed(Script script, int expectedSize)
		{
			var compressor = new ScriptCompressor(script);
			var compressed = compressor.ToBytes();
			Assert.Equal(expectedSize, compressed.Length);

			compressor = new ScriptCompressor();
			compressor.ReadWrite(compressed);
			AssertEx.CollectionEquals(compressor.GetScript().ToBytes(), script.ToBytes());

			var compressed2 = compressor.ToBytes();
			AssertEx.CollectionEquals(compressed, compressed2);
			return compressor.GetScript();
		}

        private Transaction BuildMessageTransaction(byte[] pushData, uint256 prevOutHash)
        {
            Transaction t = new Transaction();
            t.Inputs.Add(new TxIn());
            t.Inputs[0].PrevOut.Hash = prevOutHash;
            t.Inputs[0].PrevOut.N = 1;
            t.Inputs[0].ScriptSig = new Script(Op.GetPushOp(new byte[65]));

            t.Outputs.Add(new TxOut());
            t.Outputs[0].Value = 90 * Money.CENT;

            // TX_NULL_DATA
            t.Outputs[0].ScriptPubKey = new Script() + OpcodeType.OP_RETURN + pushData;

            return t;
        }

        private Transaction[] SetupDummyInputs(CoinsView coinsRet)
        {
            Transaction[] dummyTransactions = Enumerable.Range(0, 2).Select(_ => new Transaction()).ToArray();

            // Add some keys to the keystore:
            Key[] key = Enumerable.Range(0, 4).Select((_, i) => new Key(i % 2 != 0)).ToArray();


            // Create some dummy input transactions
            dummyTransactions[0].Outputs.AddRange(Enumerable.Range(0, 2).Select(_ => new TxOut()));
            dummyTransactions[0].Outputs[0].Value = 11 * Money.CENT;
            dummyTransactions[0].Outputs[0].ScriptPubKey = dummyTransactions[0].Outputs[0].ScriptPubKey + key[0].PubKey.ToBytes() + OpcodeType.OP_CHECKSIG;
            dummyTransactions[0].Outputs[1].Value = 50 * Money.CENT;
            dummyTransactions[0].Outputs[1].ScriptPubKey = dummyTransactions[0].Outputs[1].ScriptPubKey + key[1].PubKey.ToBytes() + OpcodeType.OP_CHECKSIG;
            coinsRet.AddTransaction(dummyTransactions[0], 0);


            dummyTransactions[1].Outputs.AddRange(Enumerable.Range(0, 2).Select(_ => new TxOut()));
            dummyTransactions[1].Outputs[0].Value = 21 * Money.CENT;
            dummyTransactions[1].Outputs[0].ScriptPubKey = key[2].PubKey.GetAddress(Network.BitcoinMain).ScriptPubKey;
            dummyTransactions[1].Outputs[1].Value = 22 * Money.CENT;
            dummyTransactions[1].Outputs[1].ScriptPubKey = key[3].PubKey.GetAddress(Network.BitcoinMain).ScriptPubKey;
            coinsRet.AddTransaction(dummyTransactions[1], 0);


            return dummyTransactions;
        }
    }
}
