using System;
using System.Collections.Generic;
using System.Text;

namespace NBitcoin.Crypto
{
    public class RsaPublicKey
    {
        private static readonly string propertySeparator = ",";
        private static NBitcoin.DataEncoders.HexEncoder he = new NBitcoin.DataEncoders.HexEncoder();

        public byte[] Exponent { get; set; }

        public byte[] Modulus { get; set; }

        public string ToHex()
        {
            return String.Join(RsaPublicKey.propertySeparator, he.EncodeData(this.Exponent), he.EncodeData(this.Modulus));
        }

        public static RsaPublicKey FromHex(string hexString)
        {
            string[] properties = hexString.Split(new string[] { RsaPublicKey.propertySeparator }, StringSplitOptions.None);

            return new RsaPublicKey()
            {
                Exponent = he.DecodeData(properties[0]),
                Modulus = he.DecodeData(properties[1])
            };
        }
    }
}
