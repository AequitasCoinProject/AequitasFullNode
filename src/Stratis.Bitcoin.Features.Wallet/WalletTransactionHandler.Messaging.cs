using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Extensions.Logging;
using NBitcoin;
using NBitcoin.Policy;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC.Multiplier;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Stratis.Bitcoin.Features.Wallet.Interfaces;
using Stratis.Bitcoin.Utilities;

namespace Stratis.Bitcoin.Features.Wallet
{
    public partial class WalletTransactionHandler : IWalletTransactionHandler
    {
        private void AddMessage(TransactionBuildContext context)
        {
            if (context.Message == null) return;

            //// generate RSA encryption private and public keys based on the wallet's private keys
            Wallet wallet = this.walletManager.GetWallet(context.AccountReference.WalletName);
            AsymmetricCipherKeyPair rsaKeyPair = GetRSAKeyPairFromWallet(wallet, context.WalletPassword);
            RsaKeyParameters rsaPublicKey = rsaKeyPair.Public as RsaKeyParameters;
            RsaPrivateCrtKeyParameters rsaPrivateKey = rsaKeyPair.Private as RsaPrivateCrtKeyParameters;

            //context.TransactionBuilder.SendMessage(
            //    context.Message, context.EncryptMessage,
            //    rsaPublicKey.Exponent.ToByteArray(), rsaPublicKey.Modulus.ToByteArray(),
            //    rsaPrivateKey.DP.ToByteArray(), rsaPrivateKey.DQ.ToByteArray(),
            //    rsaPrivateKey.Exponent.ToByteArray(), rsaPrivateKey.Modulus.ToByteArray(),
            //    rsaPrivateKey.P.ToByteArray(), rsaPrivateKey.PublicExponent.ToByteArray(),
            //    rsaPrivateKey.Q.ToByteArray(), rsaPrivateKey.QInv.ToByteArray()
            //    );
        }

        public static AsymmetricCipherKeyPair GetRSAKeyPairFromWallet(Wallet wallet, string walletPassword, int rsaKeySize = 4096, CoinType coinType = CoinType.Stratis)
        {
            HdAccount hdAccount = wallet.GetAccountsByCoinType(coinType).FirstOrDefault();
            string privateKeyChainId = hdAccount.ExtendedPubKey + "-" + rsaKeySize;

            // temporary caching of private keys
            Dictionary<string, byte[]> privateKeyChainCache = new Dictionary<string, byte[]>();
            privateKeyChainCache.Add(
                "xpub6DPhctexGgLNq2TrH9Vfdio8tjauufisViy9eyyBYN8igjn6VpMMdf1PJe8PEeoRePqUGdbKkCXWwdM3r1zK8cKjcJKQkdVVJ1ci7wS29XT-4096", new byte[] 
                {   0xf4, 0xb0, 0x78, 0x15, 0xf3, 0xa2, 0xd4, 0xe2, 0x78, 0x61, 0xab, 0x59, 0x70, 0x27, 0x4c, 0x70,
                    0x22, 0x97, 0x7e, 0x9a, 0x19, 0xe0, 0x4e, 0xd2, 0x88, 0x56, 0xfe, 0xe7, 0x7b, 0x70, 0x6b, 0x4c,
                    0xa5, 0x9a, 0x6e, 0xa2, 0x38, 0xad, 0xd6, 0xd4, 0x92, 0x2e, 0x05, 0xa6, 0x4a, 0x6f, 0xa0, 0x71,
                    0xa1, 0xd8, 0xf1, 0x89, 0xc3, 0xd4, 0xf2, 0xfe, 0xc0, 0x39, 0x3c, 0xfb, 0x67, 0xa6, 0x1d, 0xcd,
                    0x33, 0x94, 0x1c, 0x30, 0x86, 0x7c, 0x86, 0x91, 0xb8, 0xac, 0x65, 0xe4, 0x67, 0x86, 0xa5, 0x51,
                    0x38, 0xdf, 0x5a, 0x3e, 0x34, 0x4c, 0x42, 0x0e, 0xd2, 0x8e, 0x85, 0x05, 0x7f, 0xef, 0x17, 0x7f,
                    0x1f, 0x55, 0x97, 0x61, 0xde, 0xbd, 0xdd, 0xe6, 0x13, 0xf1, 0x90, 0x7b, 0xba, 0xed, 0x23, 0xa4,
                    0x92, 0x8b, 0x1d, 0xe8, 0x27, 0xb8, 0x09, 0x4a, 0xab, 0x64, 0x55, 0xa7, 0x22, 0x89, 0x3e, 0x26,
                    0xb4, 0xc2, 0x7f, 0x47, 0x3b, 0x6a, 0xcb, 0xd9, 0x44, 0xb6, 0xe5, 0x43, 0x43, 0x94, 0x70, 0x98,
                    0xbe, 0xbd, 0x71, 0x8d, 0x54, 0xff, 0x36, 0x73, 0x5c, 0xe4, 0x9e, 0x38, 0xc2, 0x1f, 0x43, 0x65,
                    0xc3, 0x19, 0x03, 0x64, 0x2e, 0x2c, 0xaa, 0xba, 0x85, 0x1a, 0xfa, 0x3d, 0x23, 0x69, 0x2c, 0xfb,
                    0xea, 0xa8, 0xb7, 0xdd, 0x3d, 0xc0, 0x4a, 0x4c, 0x8e, 0x0e, 0x26, 0x83, 0xe5, 0x64, 0xce, 0x66,
                    0xd4, 0x9c, 0x44, 0x24, 0xfd, 0x6a, 0xb7, 0xfd, 0x5e, 0xfe, 0xe9, 0x9e, 0x35, 0xa2, 0x3f, 0xa0,
                    0x98, 0x30, 0x6f, 0x2b, 0x47, 0xc4, 0x1d, 0x6d, 0xb4, 0x2b, 0xf7, 0x58, 0x29, 0x71, 0x76, 0x3c,
                    0xa7, 0x58, 0x44, 0x7d, 0xa0, 0xa2, 0x49, 0x95, 0x20, 0xad, 0x65, 0xc4, 0x44, 0x88, 0x56, 0xf0,
                    0x38, 0xb7, 0x7e, 0x7d, 0x00, 0x35, 0xf0, 0xa2, 0xe4, 0x0b, 0x25, 0x28, 0xdd, 0x22, 0xbe, 0x43,
                    0x53, 0xed, 0x79, 0xb6, 0xaa, 0x00, 0x4b, 0xff, 0x8f, 0x32, 0xb9, 0xee, 0x3a, 0xc4, 0x90, 0x16,
                    0x79, 0x7e, 0x2a, 0xad, 0xc4, 0x75, 0x53, 0x7b, 0xa5, 0x9d, 0xaa, 0xae, 0xa9, 0xc9, 0xaa, 0x49,
                    0x9b, 0x46, 0x7b, 0x70, 0xec, 0xc3, 0x44, 0x47, 0x39, 0x13, 0xa5, 0x0e, 0x7d, 0x0b, 0x61, 0x20,
                    0x08, 0x4d, 0x9f, 0x52, 0x34, 0x5e, 0x92, 0x75, 0x21, 0xe8, 0x88, 0x71, 0x7d, 0x75, 0xa5, 0xc7,
                    0x53, 0x00, 0x2d, 0x9a, 0x96, 0x2d, 0x9d, 0xfd, 0xa3, 0x7c, 0x57, 0x60, 0x9b, 0xd9, 0x17, 0x20,
                    0xfd, 0xfa, 0xbc, 0xf4, 0x45, 0x85, 0x54, 0x20, 0xf9, 0x10, 0xe3, 0xcb, 0x01, 0x64, 0x67, 0x2f,
                    0xc2, 0xe9, 0x25, 0x36, 0xaa, 0x45, 0xd5, 0x18, 0xcb, 0x93, 0xa1, 0xf2, 0x8c, 0x16, 0x5d, 0x09,
                    0x63, 0x5f, 0x7f, 0x0d, 0x94, 0xd5, 0x11, 0x6a, 0x04, 0x4b, 0xfd, 0x33, 0x0e, 0xe2, 0xbc, 0x97,
                    0xaa, 0x27, 0x18, 0xf0, 0x1b, 0x62, 0xb0, 0xe5, 0x35, 0x50, 0xdf, 0x24, 0x36, 0xb0, 0x48, 0x13,
                    0x79, 0x80, 0xab, 0xa0, 0x4e, 0x65, 0x99, 0xab, 0xe3, 0x4e, 0x45, 0x04, 0x66, 0x13, 0x61, 0xd9,
                    0x2e, 0x64, 0x53, 0x5d, 0x98, 0x93, 0x49, 0x90, 0x3d, 0xea, 0x47, 0xdc, 0x27, 0x3c, 0x8a, 0xff,
                    0x5a, 0x3b, 0xfb, 0xbd, 0x5d, 0x58, 0xea, 0x5d, 0x0a, 0xef, 0xdf, 0x60, 0x86, 0xf3, 0x17, 0xd3,
                    0x9e, 0x31, 0x6a, 0x11, 0x98, 0xce, 0xf3, 0x3a, 0xee, 0xb0, 0x93, 0x8b, 0x9d, 0xe1, 0x90, 0xd0,
                    0x9a, 0x97, 0x97, 0x9a, 0x51, 0x3a, 0x59, 0xe6, 0x56, 0xa5, 0xc5, 0x68, 0x7d, 0x0e, 0xd3, 0xaf,
                    0x64, 0x67, 0x59, 0x7a, 0xf8, 0x09, 0x2f, 0x3d, 0x12, 0x44, 0xb6, 0x19, 0xd8, 0x8e, 0x49, 0x43,
                    0x47, 0x05, 0x5c, 0x97, 0x73, 0xde, 0x88, 0xa6, 0x02, 0x86, 0xfa, 0x06, 0xd4, 0xc8, 0x13, 0xe2 });

            if (!privateKeyChainCache.ContainsKey(privateKeyChainId))
            {
                List<byte> privateKeys = new List<byte>();
                foreach (HdAddress address in hdAccount.ExternalAddresses)
                {
                    if (privateKeys.Count * 8 >= rsaKeySize) break;

                    BitcoinExtKey privateKey = wallet.GetExtendedPrivateKeyForAddress(walletPassword, address) as BitcoinExtKey;
                    privateKeys.AddRange(privateKey.ExtKey.ChainCode);

                    //PubKey publicKey = privateKey.PrivateKey.PubKey.Decompress();
                    //string uncompressedPublicKey = publicKey.ToString().Substring(2);
                }
                privateKeyChainCache.Add(privateKeyChainId, privateKeys.ToArray());
            }

            var randomSeedGenerator = System.Security.Cryptography.RandomNumberGenerator.Create();
            byte[] seed = new byte[rsaKeySize / 8];
            randomSeedGenerator.GetBytes(seed);

            VmpcRandomGenerator randomGenerator = new VmpcRandomGenerator();
            randomGenerator.AddSeedMaterial(seed);

            //CryptoApiRandomGenerator randomGenerator = new CryptoApiRandomGenerator();
            var secureRandom = new SecureRandom(randomGenerator);
            var keyGenerationParameters = new KeyGenerationParameters(secureRandom, rsaKeySize);

            var privateKeyBasedRsaKeyPairGenerator = new PrivateKeyBasedRsaKeyPairGenerator();
            privateKeyBasedRsaKeyPairGenerator.Init(keyGenerationParameters, privateKeyChainCache[privateKeyChainId]);
            var result = privateKeyBasedRsaKeyPairGenerator.GenerateKeyPair();

            return result;
        }

        /// <summary>
        /// Deterministically generates one particular RSA keypair based on a private key
        /// </summary>
        private class PrivateKeyBasedRsaKeyPairGenerator : RsaKeyPairGenerator
        {
            private static readonly int[] SPECIAL_E_VALUES = new int[] { 3, 5, 17, 257, 65537 };
            private static readonly int SPECIAL_E_HIGHEST = SPECIAL_E_VALUES[SPECIAL_E_VALUES.Length - 1];
            private static readonly int SPECIAL_E_BITS = BigInteger.ValueOf(SPECIAL_E_HIGHEST).BitLength;

            private byte[] generatorKey;

            public void Init(KeyGenerationParameters parameters, byte[] privateKey)
            {
                this.generatorKey = privateKey;
                base.Init(parameters);
            }

            public override AsymmetricCipherKeyPair GenerateKeyPair()
            {
                for (; ; )
                {
                    //
                    // p and q values should have a length of half the strength in bits
                    //
                    int strength = this.parameters.Strength;
                    int pBitlength = (strength + 1) / 2;
                    int qBitlength = strength - pBitlength;
                    int mindiffbits = strength / 3;
                    int minWeight = strength >> 2;

                    if ((pBitlength % 8 != 0) || (qBitlength % 8 != 0))
                    {
                        throw new Exception($"The bitlength of both p and q must be a multilple of 8.");
                    }

                    byte[] pBytes = this.generatorKey.Take(pBitlength / 8).ToArray();
                    BigInteger pStartValue = new BigInteger(+1, pBytes);

                    byte[] qBytes = this.generatorKey.Skip(Math.Max(0, this.generatorKey.Count() - (qBitlength / 8))).ToArray();
                    BigInteger qStartValue = new BigInteger(+1, qBytes);

                    BigInteger e = this.parameters.PublicExponent;

                    // TODO Consider generating safe primes for p, q (see DHParametersHelper.generateSafePrimes)
                    // (then p-1 and q-1 will not consist of only small factors - see "Pollard's algorithm")

                    int pIndex = 1;
                    int qIndex = 0;
                    //BigInteger p = ChooseRandomPrime(pBitlength, e);
                    BigInteger p = ChooseNthPrime(pStartValue, e, pIndex);
                    BigInteger q, n;
                    q = qStartValue;

                    //
                    // generate a modulus of the required length
                    //
                    for (; ; )
                    {
                        //qIndex++;
                        if (q.BitLength < qBitlength)
                        {
                            // we have overflown
                            qStartValue = new BigInteger(+1, Enumerable.Repeat((byte)0xFF, qBitlength / 8).ToArray());
                        }
                        else
                        {
                            qStartValue = new BigInteger(+1, q.ToByteArrayUnsigned());
                        }
                        q = ChooseNthPrime(qStartValue, e, qIndex);

                        // p and q should not be too close together (or equal!)
                        BigInteger diff = q.Subtract(p).Abs();
                        if (diff.BitLength < mindiffbits)
                            continue;

                        //
                        // calculate the modulus
                        //
                        n = p.Multiply(q);

                        if (n.BitLength != strength)
                        {
                            //
                            // if we get here our primes aren't big enough, make the largest
                            // of the two p and try again
                            //
                            p = p.Max(q);
                            continue;
                        }

                        /*
                         * Require a minimum weight of the NAF representation, since low-weight composites may
                         * be weak against a version of the number-field-sieve for factoring.
                         *
                         * See "The number field sieve for integers of low weight", Oliver Schirokauer.
                         */
                        if (WNafUtilities.GetNafWeight(n) < minWeight)
                        {
                            p = ChooseNthPrime(pStartValue, e, pIndex);
                            continue;
                        }

                        break;
                    }

                    if (p.CompareTo(q) < 0)
                    {
                        BigInteger tmp = p;
                        p = q;
                        q = tmp;
                    }

                    BigInteger pSub1 = p.Subtract(One);
                    BigInteger qSub1 = q.Subtract(One);
                    //BigInteger phi = pSub1.Multiply(qSub1);
                    BigInteger gcd = pSub1.Gcd(qSub1);
                    BigInteger lcm = pSub1.Divide(gcd).Multiply(qSub1);

                    //
                    // calculate the private exponent
                    //
                    BigInteger d = e.ModInverse(lcm);

                    if (d.BitLength <= qBitlength)
                        continue;

                    //
                    // calculate the CRT factors
                    //
                    BigInteger dP = d.Remainder(pSub1);
                    BigInteger dQ = d.Remainder(qSub1);
                    BigInteger qInv = q.ModInverse(p);

                    return new AsymmetricCipherKeyPair(
                        new RsaKeyParameters(false, n, e),
                        new RsaPrivateCrtKeyParameters(n, e, d, p, q, dP, dQ, qInv));
                }
            }

            /// <summary>
            /// Chooses the nth particular prime which is lower than the startValue
            /// </summary>
            /// <param name="startValue">The value which we start to look for a prime from</param>
            /// <param name="e">Exponent</param>
            /// <param name="n">The index of the prime</param>
            /// <returns></returns>
            protected BigInteger ChooseNthPrime(BigInteger startValue, BigInteger e, int n)
            {
                bool eIsKnownOddPrime = (e.BitLength <= SPECIAL_E_BITS) && Arrays.Contains(SPECIAL_E_VALUES, e.IntValue);

                BigInteger p = new BigInteger(startValue.ToByteArray());

                while (true)
                {
                    if (p.BitLength < startValue.BitLength)
                    {
                        p = new BigInteger(startValue.ToByteArray());
                    }

                    p = p.Subtract(BigInteger.One);

                    if (!p.TestBit(0)) continue;

                    if (p.Mod(e).Equals(One))
                        continue;

                    if (!p.IsProbablePrime(this.parameters.Certainty))
                        continue;

                    if (!eIsKnownOddPrime && !e.Gcd(p.Subtract(One)).Equals(One))
                        continue;

                    // p is a prime
                    n--;
                    if (n <= 0) break;
                }

                return p;
            }
        }        
    }
}
