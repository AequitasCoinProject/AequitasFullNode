﻿using System;
using System.IO;
using System.Linq;
using System.Threading;
using Xunit;

namespace NBitcoin.Tests
{
    public class NetworkTests
    {
        public NetworkTests()
        {
            // These flags may get set due to static network initializers
            // which include the initializers for Stratis.
            Transaction.TimeStamp = false;
            Block.BlockSignature = false;
        }

        [Fact]
        [Trait("UnitTest", "UnitTest")]
        public void CanGetNetworkFromName()
        {
            Assert.Equal(Network.GetNetwork("main"), Network.BitcoinMain);
            Assert.Equal(Network.GetNetwork("reg"), Network.BitcoinRegTest);
            Assert.Equal(Network.GetNetwork("regtest"), Network.BitcoinRegTest);
            Assert.Equal(Network.GetNetwork("testnet"), Network.BitcoinTest);
            Assert.Null(Network.GetNetwork("invalid"));
        }

        [Fact]
        [Trait("UnitTest", "UnitTest")]
        public void CanCreateNetwork()
        {
            NetworkBuilder builder = new NetworkBuilder();
            builder.CopyFrom(Network.BitcoinMain);
            builder.SetNetworkName(null);
            Assert.Throws<InvalidOperationException>(() => builder.BuildAndRegister());
            builder.SetNetworkName("new");
            builder.AddAlias("newalias");
            var network = builder.BuildAndRegister();
            Assert.Throws<InvalidOperationException>(() => builder.BuildAndRegister());

            Assert.Equal(network, Network.GetNetwork("new"));
            Assert.Equal(network, Network.GetNetwork("newalias"));

            CanGetNetworkFromName();

            Assert.Contains(network, Network.GetNetworks());
        }

        [Fact]
        [Trait("UnitTest", "UnitTest")]
        public void ReadMagicByteWithFirstByteDuplicated()
        {
            var bytes = Network.BitcoinMain.MagicBytes.ToList();
            bytes.Insert(0, bytes.First());

            using(var memstrema = new MemoryStream(bytes.ToArray()))
            {
                var found = Network.BitcoinMain.ReadMagic(memstrema, new CancellationToken());
                Assert.True(found);
            }
        }
    }
}
