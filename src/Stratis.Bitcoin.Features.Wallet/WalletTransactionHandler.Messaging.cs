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
            //// generate RSA encryption private and public keys based on the wallet's private keys
            Wallet wallet = this.walletManager.GetWallet(context.AccountReference.WalletName);
            AsymmetricCipherKeyPair rsaKeyPair = GetRSAKeyPairFromWallet(wallet, context.WalletPassword);
            RsaKeyParameters rsaPublicKey = rsaKeyPair.Public as RsaKeyParameters;
            RsaPrivateCrtKeyParameters rsaPrivateKey = rsaKeyPair.Private as RsaPrivateCrtKeyParameters;

            context.TransactionBuilder.SendMessage(
                context.Message, context.EncryptMessage,
                rsaPublicKey.Exponent.ToByteArray(), rsaPublicKey.Modulus.ToByteArray(),
                rsaPrivateKey.DP.ToByteArray(), rsaPrivateKey.DQ.ToByteArray(),
                rsaPrivateKey.Exponent.ToByteArray(), rsaPrivateKey.Modulus.ToByteArray(),
                rsaPrivateKey.P.ToByteArray(), rsaPrivateKey.PublicExponent.ToByteArray(),
                rsaPrivateKey.Q.ToByteArray(), rsaPrivateKey.QInv.ToByteArray()
                );
        }

        public static AsymmetricCipherKeyPair GetRSAKeyPairFromWallet(Wallet wallet, string walletPassword, int rsaKeySize = 4096, CoinType coinType = CoinType.Stratis)
        {
            HdAccount hdAccount = wallet.GetAccountsByCoinType(coinType).FirstOrDefault();

            List<byte> privateKeys = new List<byte>();

            foreach (HdAddress address in hdAccount.ExternalAddresses)
            {
                if (privateKeys.Count * 8 > rsaKeySize) break;
            
                BitcoinExtKey privateKey = wallet.GetExtendedPrivateKeyForAddress(walletPassword, address) as BitcoinExtKey;
                privateKeys.AddRange(privateKey.ExtKey.ChainCode);

                //PubKey publicKey = privateKey.PrivateKey.PubKey.Decompress();
                //string uncompressedPublicKey = publicKey.ToString().Substring(2);
            }

            CryptoApiRandomGenerator randomGenerator = new CryptoApiRandomGenerator();
            var secureRandom = new SecureRandom(randomGenerator);
            var keyGenerationParameters = new KeyGenerationParameters(secureRandom, rsaKeySize);

            var privateKeyBasedRsaKeyPairGenerator = new PrivateKeyBasedRsaKeyPairGenerator();
            privateKeyBasedRsaKeyPairGenerator.Init(keyGenerationParameters, privateKeys.ToArray());
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

                    //
                    // generate a modulus of the required length
                    //
                    for (; ; )
                    {
                        qIndex++;
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
