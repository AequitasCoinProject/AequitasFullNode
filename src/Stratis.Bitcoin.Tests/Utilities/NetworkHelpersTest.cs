using System;
using NBitcoin;
using Stratis.Bitcoin.Utilities;
using Xunit;

namespace Stratis.Bitcoin.Tests.Utilities
{
    public class NetworkHelpersTest
    {
        [Fact]
        public void GetMainNetworkReturnsNetworkMain()
        {
            Network main = Network.Main;
            Network network = NetworkHelpers.GetNetwork("main");
            Assert.Equal(Network.BitcoinMain, network);
        }

        [Fact]
        public void GetMainNetNetworkReturnsNetworkMain()
        {
            Network main = Network.Main;
            Network network = NetworkHelpers.GetNetwork("mainnet");
            Assert.Equal(Network.BitcoinMain, network);
        }

        [Fact]
        public void GetTestNetworkReturnsNetworkTest()
        {
            Network test = Network.TestNet;
            Network network = NetworkHelpers.GetNetwork("test");
            Assert.Equal(Network.BitcoinTest, network);
        }

        [Fact]
        public void GetTestNetNetworkReturnsNetworkTest()
        {
            Network test = Network.TestNet;
            Network network = NetworkHelpers.GetNetwork("testnet");
            Assert.Equal(Network.BitcoinTest, network);
        }

        [Fact]
        public void GetNetworkIsCaseInsensitive()
        {
            Network test = Network.TestNet;
            Network main = Network.Main;

            Network testNetwork = NetworkHelpers.GetNetwork("Test");
            Assert.Equal(Network.BitcoinTest, testNetwork);

            Network mainNetwork = NetworkHelpers.GetNetwork("MainNet");
            Assert.Equal(Network.BitcoinMain, mainNetwork);
        }

        [Fact]
        public void WrongNetworkThrowsArgumentException()
        {
            Exception exception = Record.Exception(() => NetworkHelpers.GetNetwork("myNetwork"));
            Assert.NotNull(exception);
            Assert.IsType<ArgumentException>(exception);
        }
    }
}
