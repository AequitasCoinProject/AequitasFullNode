using NBitcoin.DataEncoders;

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
