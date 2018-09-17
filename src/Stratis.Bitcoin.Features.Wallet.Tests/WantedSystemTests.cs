using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
#if !NOCONSENSUSLIB
using System.Net.Http;
#endif
using Xunit;
using NBitcoin;
using NBitcoin.Crypto;
using NBitcoin.BitcoinCore;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Stratis.Bitcoin.Features.Wallet.Controllers;
using Xunit.Abstractions;

namespace Stratis.Bitcoin.Features.Wallet.Tests
{
	public class WantedSystemTests : WalletTestBase
    {
        private readonly ITestOutputHelper _testOutputHelper;

        private readonly Network network;

        public WantedSystemTests(ITestOutputHelper testOutputHelper)// Network network)
        {
            //this.network = network;
            _testOutputHelper = testOutputHelper;
        }

        [Fact]
        [Trait("UnitTest", "UnitTest")]
        public void CanCompressMessageAsScript()
        {
            var coinsView = new CoinsView(this.network);
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
            coinsView.AddTransaction(this.network.Consensus, dummyTransactions[1], 0);

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
            Assert.Equal(compressor.GetScript().ToBytes(), script.ToBytes());

            var compressed2 = compressor.ToBytes();
            Assert.Equal(compressed, compressed2);
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
            coinsRet.AddTransaction(this.network.Consensus, dummyTransactions[0], 0);


            dummyTransactions[1].Outputs.AddRange(Enumerable.Range(0, 2).Select(_ => new TxOut()));
            dummyTransactions[1].Outputs[0].Value = 21 * Money.CENT;
            dummyTransactions[1].Outputs[0].ScriptPubKey = key[2].PubKey.GetAddress(Network.GetNetwork("BitcoinMain")).ScriptPubKey;
            dummyTransactions[1].Outputs[1].Value = 22 * Money.CENT;
            dummyTransactions[1].Outputs[1].ScriptPubKey = key[3].PubKey.GetAddress(Network.GetNetwork("BitcoinMain")).ScriptPubKey;
            coinsRet.AddTransaction(this.network.Consensus, dummyTransactions[1], 0);


            return dummyTransactions;
        }


        [Fact]
        [Trait("UnitTest", "UnitTest")]
        public void TestRSAKeyGeneration()
        {
            string[] seeds = {
                //"password",
                //"B19vFoBiXzEB",
                //"pF8M8xoE5eoF",
                //"Hy40jrmpXdQx",
                //"V2J6M7WvtbnvwRwQnxDlt0LNdCJiqgvl6sZ5",
                "wfwEaOHczdyz5IXiKHuX4ZiuyNiwZ6tAa0gpuOnb1G1QWhkcRxDYRHMd6i5dcwlPuvYXGbXudrLd5neF5HecvcPjy74fvwEopor6",
                "wfwEaOHczdyz5IXiKHuX4ZiuyNiwZ6tAa0gpuOnb1G1QWhkcRxDYRHMd6i5dcwlPuvYXGbXudrLd5neF5HecvcPjy74fvwEopor6",
                "70P4W43s2j4Sm3PE03xBCtrzYfl0UIvhOnYa9Pl7CBBmBFGOFmB1cWO6bLbnzcIQpA6BpP8BpXPzh6KzgDXek2uxMLQQM26iR6SQ",
                "bKnQtlUDemihGZOMwqT4pWVKe7zkWqp8oDKgzxBgklEXFwpugMbfUA4ruNJQSX8awetXIY7jYKqtLdVpBaP6kZU3PThc8Acw9om1",
                "b58lTEJ1btzuu3FXKv4zD4bsRXLWr18GBwt2k27kM5XJCg1mUmcZ1vQLxCEgATmze3upKxSH745gjy9pws4jjpoPEfq80dj8LhOX"
            };

            for (int i = 0; i < seeds.Length; i++)
            {
                DateTime time = DateTime.UtcNow;
                this._testOutputHelper.WriteLine($"Generating keys for '{seeds[i]}'");
                GenerateKeys(seeds[i]);
                this._testOutputHelper.WriteLine($"Generation completed in {(DateTime.UtcNow - time).TotalSeconds.ToString("0.000")} seconds.");
                this._testOutputHelper.WriteLine("");
            }

        }

        private void GenerateKeys(string seed)
        {
            // generate the RSA keypair for the address
            AsymmetricCipherKeyPair rsaKeyPair = WalletController.GetRSAKeyPairFromSeed(seed);

            RsaKeyParameters rsaPublicKey = rsaKeyPair.Public as RsaKeyParameters;
            RsaPublicKey pbk = new RsaPublicKey()
            {
                Exponent = rsaPublicKey.Exponent.ToByteArrayUnsigned(),
                Modulus = rsaPublicKey.Modulus.ToByteArrayUnsigned()
            };

            RsaPrivateCrtKeyParameters rsaPrivateKey = rsaKeyPair.Private as RsaPrivateCrtKeyParameters;
            RsaPrivateKey prk = new RsaPrivateKey()
            {
                DP = rsaPrivateKey.DP.ToByteArrayUnsigned(),
                DQ = rsaPrivateKey.DQ.ToByteArrayUnsigned(),
                Exponent = rsaPrivateKey.Exponent.ToByteArrayUnsigned(),
                Modulus = rsaPrivateKey.Modulus.ToByteArrayUnsigned(),
                P = rsaPrivateKey.P.ToByteArrayUnsigned(),
                PublicExponent = rsaPrivateKey.PublicExponent.ToByteArrayUnsigned(),
                Q = rsaPrivateKey.Q.ToByteArrayUnsigned(),
                QInv = rsaPrivateKey.QInv.ToByteArrayUnsigned()
            };

            this._testOutputHelper.WriteLine($"Public key: {pbk.ToHex()}");
            this._testOutputHelper.WriteLine($"Private key: {prk.ToHex()}");
        }
    }
}
