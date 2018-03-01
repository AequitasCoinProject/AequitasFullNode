using System;

namespace NBitcoin.Crypto
{
    public class RsaPrivateKey
    {
        private static readonly string propertySeparator = ",";
        private static NBitcoin.DataEncoders.HexEncoder he = new NBitcoin.DataEncoders.HexEncoder();

        public byte[] DP { get; set; }

        public byte[] DQ { get; set; }

        public byte[] Exponent { get; set; }

        public byte[] Modulus { get; set; }

        public byte[] P { get; set; }

        public byte[] PublicExponent { get; set; }

        public byte[] Q { get; set; }

        public byte[] QInv { get; set; }

        public string ToHex()
        {
            return String.Join(RsaPrivateKey.propertySeparator,
                he.EncodeData(this.DP), he.EncodeData(this.DQ),
                he.EncodeData(this.Exponent), he.EncodeData(this.Modulus),
                he.EncodeData(this.P), he.EncodeData(this.PublicExponent),
                he.EncodeData(this.Q), he.EncodeData(this.QInv)
                );
        }

        public static RsaPrivateKey FromHex(string hexString)
        {
            string[] properties = hexString.Split(new string[] { RsaPrivateKey.propertySeparator }, StringSplitOptions.None);

            return new RsaPrivateKey()
            {
                DP = he.DecodeData(properties[0]),
                DQ = he.DecodeData(properties[1]),
                Exponent = he.DecodeData(properties[2]),
                Modulus = he.DecodeData(properties[3]),
                P = he.DecodeData(properties[4]),
                PublicExponent = he.DecodeData(properties[5]),
                Q = he.DecodeData(properties[6]),
                QInv = he.DecodeData(properties[7])
            };
        }

    }
}
