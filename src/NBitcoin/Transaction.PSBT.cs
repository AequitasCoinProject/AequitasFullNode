using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using NBitcoin.Crypto;
using NBitcoin.DataEncoders;
using NBitcoin.Protocol;
using NBitcoin.RPC;

namespace NBitcoin
{
    //https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
    public static class PartiallySignedBitcoinTransaction
    {
        public static byte[] ToPSBT(this Transaction tx)
        {
            return new byte[0];
        }

        public static string ToPSBTHex(this Transaction tx)
        {
            return Encoders.Hex.EncodeData(tx.ToPSBT());
        }
    }
}
