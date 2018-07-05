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
        public static Network StratisMain => Network.GetNetwork("StratisMain") ?? new StratisNetwork().Init(NetworkInitializationMode.Main);

        public static Network StratisTest => Network.GetNetwork("StratisTest") ?? new StratisNetwork().Init(NetworkInitializationMode.Test);

        public static Network StratisRegTest => Network.GetNetwork("StratisRegTest") ?? new StratisNetwork().Init(NetworkInitializationMode.RegTest);
    }


    public class StratisNetwork
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
                    network = InitRegTest();
                    break;
            }

            if (network != null)
            {
                Network.NetworksContainer.TryAdd(network.Name.ToLowerInvariant(), network);
                return network;
            }
            else
            {
                throw new Exception("The initialization parameter is unknown.");
            }
        }

        private Network InitMain()
        {
            Network network = new StratisMain();
            network.MoneyUnits = GetMoneyUnitsMain();
            return network;
        }

        private Network InitTest()
        {
            Network network = new StratisTest();
            network.MoneyUnits = GetMoneyUnitsTest();
            return network;
        }

        private Network InitRegTest()
        {
            Network network = new StratisRegTest();
            network.MoneyUnits = GetMoneyUnitsTest();
            return network;
        }

        private Block CreateStratisGenesisBlock(uint nTime, uint nNonce, uint nBits, int nVersion, Money genesisReward)
        {
            string pszTimestamp = "http://www.theonion.com/article/olympics-head-priestess-slits-throat-official-rio--53466";
            return CreateStratisGenesisBlock(pszTimestamp, nTime, nNonce, nBits, nVersion, genesisReward);
        }

        private Block CreateStratisGenesisBlock(string pszTimestamp, uint nTime, uint nNonce, uint nBits, int nVersion, Money genesisReward)
        {
            Transaction txNew = new Transaction();
            txNew.Version = 1;
            txNew.Time = nTime;
            txNew.AddInput(new TxIn()
            {
                ScriptSig = new Script(Op.GetPushOp(0), new Op()
                {
                    Code = (OpcodeType)0x1,
                    PushData = new[] { (byte)42 }
                }, Op.GetPushOp(Encoders.ASCII.DecodeData(pszTimestamp)))
            });
            txNew.AddOutput(new TxOut()
            {
                Value = genesisReward,
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

        private MoneyUnits GetMoneyUnitsMain()
        {
            return new MoneyUnits("STRAT",
                new MoneyUnit[] {
                    new MoneyUnit("STRAT", 100000000),
                    new MoneyUnit("s", 1)
                });
        }

        private MoneyUnits GetMoneyUnitsTest()
        {
            return new MoneyUnits("STRAT-TEST",
                new MoneyUnit[] {
                    new MoneyUnit("STRAT-TEST", 100000000),
                    new MoneyUnit("s-test", 1)
                });
        }
    }
}
