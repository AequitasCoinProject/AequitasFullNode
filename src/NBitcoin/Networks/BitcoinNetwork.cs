using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using NBitcoin.BouncyCastle.Math;
using NBitcoin.DataEncoders;
using NBitcoin.Networks;
using NBitcoin.Protocol;

namespace NBitcoin
{
    public partial class Network
    {
        public static Network BitcoinMain => Network.GetNetwork("BitcoinMain") ?? new BitcoinNetwork().Init(NetworkInitializationMode.Main);

        public static Network BitcoinTest => Network.GetNetwork("BitcoinTest") ?? new BitcoinNetwork().Init(NetworkInitializationMode.Test);

        public static Network BitcoinRegTest => Network.GetNetwork("BitcoinRegTest") ?? new BitcoinNetwork().Init(NetworkInitializationMode.RegTest);
    }

    public class BitcoinNetwork
    {
        public Network Init(NetworkInitializationMode mode)
        {
            Network network = null;

            switch (mode)
            {
                case NetworkInitializationMode.Main:
                    network = InitMain();
                    break;
                case NetworkInitializationMode.Test:
                    network = InitTest();
                    break;
                case NetworkInitializationMode.RegTest:
                    network = InitReg();
                    break;
            }

            if (network != null)
            {
                Network.NetworksContainer.TryAdd(network.Name.ToLowerInvariant(), network);
                NetworksContainer.Register(network);
                return network;
            }
            else
            {
                throw new Exception("The initialization parameter is unknown.");
            }
        }

        private Network InitMain()
        {
            Network network = new BitcoinMain();
            network.MoneyUnits = GetMoneyUnitsMainAndTest();
            return network;
        }

        private Network InitTest()
        {
            Network network = new BitcoinTest();
            network.MoneyUnits = GetMoneyUnitsMainAndTest();
            return network;
        }

        private Network InitReg()
        {
            Network network = new BitcoinRegTest();
            network.MoneyUnits = GetMoneyUnitsMainAndTest();
            return network;
        }

        private Block CreateGenesisBlock(uint nTime, uint nNonce, uint nBits, int nVersion, Money genesisReward)
        {
            string pszTimestamp = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
            Script genesisOutputScript = new Script(Op.GetPushOp(Encoders.Hex.DecodeData("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f")), OpcodeType.OP_CHECKSIG);
            return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
        }

        private Block CreateGenesisBlock(string pszTimestamp, Script genesisOutputScript, uint nTime, uint nNonce, uint nBits, int nVersion, Money genesisReward)
        {
            Transaction txNew = new Transaction();
            txNew.Version = 1;
            txNew.AddInput(new TxIn()
            {
                ScriptSig = new Script(Op.GetPushOp(486604799), new Op()
                {
                    Code = (OpcodeType)0x1,
                    PushData = new[] { (byte)4 }
                }, Op.GetPushOp(Encoders.ASCII.DecodeData(pszTimestamp)))
            });
            txNew.AddOutput(new TxOut()
            {
                Value = genesisReward,
                ScriptPubKey = genesisOutputScript
            });
            Block genesis = new Block();
            genesis.Header.BlockTime = Utils.UnixTimeToDateTime(nTime);
            genesis.Header.Bits = nBits;
            genesis.Header.Nonce = nNonce;
            genesis.Header.Version = nVersion;
            genesis.Transactions.Add(txNew);
            genesis.Header.HashPrevBlock = uint256.Zero;
            genesis.UpdateMerkleRoot();
            return genesis;
        }

        private MoneyUnits GetMoneyUnitsMainAndTest()
        {
            return new MoneyUnits("BTC",
                new MoneyUnit[] {
                    new MoneyUnit("BTC", 100000000),
                    new MoneyUnit("milliBTC", 100000),
                    new MoneyUnit("bit", 100),
                    new MoneyUnit("satoshi", 1)
                });
        }
    }
}
