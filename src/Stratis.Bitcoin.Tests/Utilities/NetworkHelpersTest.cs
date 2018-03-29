using System;
using NBitcoin;
using Stratis.Bitcoin.Utilities;
using Xunit;

namespace Stratis.Bitcoin.Tests.Utilities
{
    public class NetworkHelpersTest
    {
        [Fact]
        public void GetMainNetworkRetuirnsNetworkMain()
        {
            Network network = NetworkHelpers.GetNetwork("main");
            Assert.Equal(Network.BitcoinMain, network);
        }

        [Fact]
        public void GetMainNetNetworkRetuirnsNetworkMain()
        {
            Network network = NetworkHelpers.GetNetwork("mainnet");
            Assert.Equal(Network.BitcoinMain, network);
        }

        [Fact]
        public void GetTestNetworkRetuirnsNetworkTest()
        {
            Network network = NetworkHelpers.GetNetwork("test");
            Assert.Equal(Network.BitcoinTest, network);
        }

        [Fact]
        public void GetTestNetNetworkRetuirnsNetworkTest()
        {
            Network network = NetworkHelpers.GetNetwork("testnet");
            Assert.Equal(Network.BitcoinTest, network);
        }

        [Fact]
        public void GetNetworkIsCaseInsensitive()
        {
            Network testNetwork = NetworkHelpers.GetNetwork("Test");
            Assert.Equal(Network.BitcoinTest, testNetwork);

            Network mainNetwork = NetworkHelpers.GetNetwork("MainNet");
            Assert.Equal(Network.BitcoinMain, mainNetwork);
        }

        [Fact]
        public void WrongNetworkThrowsArgumentException()
        {
            var exception = Record.Exception(() => NetworkHelpers.GetNetwork("myNetwork"));
            Assert.NotNull(exception);
            Assert.IsType<ArgumentException>(exception);
        }
    }
}
