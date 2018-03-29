using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using NBitcoin.BouncyCastle.Math;
using NBitcoin.DataEncoders;
using NBitcoin.Protocol;

namespace NBitcoin
{
    public partial class Network
    {
        static Network()
        {
            // initialize the networks
            bool saveTS = Transaction.TimeStamp;
            bool saveSig = Block.BlockSignature;
            Transaction.TimeStamp = false;
            Block.BlockSignature = false;

            Network main = Network.BitcoinMain;
            Network testNet = Network.BitcoinTest;
            Network regTest = Network.BitcoinRegTest;

            Transaction.TimeStamp = saveTS;
            Block.BlockSignature = saveSig;
        }
    }
}
