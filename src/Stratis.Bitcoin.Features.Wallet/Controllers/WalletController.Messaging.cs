using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.Extensions.Logging;
using NBitcoin;
using NBitcoin.Crypto;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC.Multiplier;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Stratis.Bitcoin.Connection;
using Stratis.Bitcoin.Features.Wallet.Helpers;
using Stratis.Bitcoin.Features.Wallet.Interfaces;
using Stratis.Bitcoin.Features.Wallet.Models;
using Stratis.Bitcoin.Interfaces;
using Stratis.Bitcoin.Utilities;
using Stratis.Bitcoin.Utilities.JsonErrors;

namespace Stratis.Bitcoin.Features.Wallet.Controllers
{
    public partial class WalletController : Controller
    { 
        /// <summary>
        /// Gets a tip fee estimate.
        /// Fee can be estimated by creating a <see cref="TransactionBuildContext"/> with no password
        /// and then building the tip transaction and retrieving the fee from the context.
        /// </summary>
        /// <param name="request">The transaction parameters.</param>
        /// <returns>The estimated fee for the transaction.</returns>
        [Route("estimate-tip-fee")]
        [HttpGet]
        public IActionResult GetTipFeeEstimate([FromQuery] TipFeeEstimateRequest request)
        {
            Guard.NotNull(request, nameof(request));

            // checks the request is valid
            if (!this.ModelState.IsValid)
            {
                return BuildErrorResponse(this.ModelState);
            }

            try
            {
                var destination = BitcoinAddress.Create(request.DestinationAddress, this.network).ScriptPubKey;
                var context = new TransactionBuildContext(
                    new WalletAccountReference(request.WalletName, request.AccountName),
                    new[] { new Recipient { Amount = new Money(500, MoneyUnit.Satoshi), ScriptPubKey = destination } }.ToList())
                {
                    FeeType = FeeType.Low,
                    MinConfirmations = 0,
                };

                return this.Json(this.walletTransactionHandler.EstimateFee(context));
            }
            catch (Exception e)
            {
                this.logger.LogError("Exception occurred: {0}", e.ToString());
                return ErrorHelpers.BuildErrorResponse(HttpStatusCode.BadRequest, e.Message, e.ToString());
            }
        }

        /// <summary>
        /// Builds a tip transaction. If the tip trancation is paid by the Tipster, the message should not be encrypted. If the tip tranaction is paid by the Reviewers, the message should be encrypted with their keys.
        /// </summary>
        /// <param name="request">The transaction parameters.</param>
        /// <returns>All the details of the transaction, including the hex used to execute it.</returns>
        [Route("build-tip-transaction")]
        [HttpPost]
        public IActionResult BuildTipTransaction([FromBody] BuildTipTransactionRequest request)
        {
            Guard.NotNull(request, nameof(request));

            // checks the request is valid
            if (!this.ModelState.IsValid)
            {
                return BuildErrorResponse(this.ModelState);
            }

            try
            {
                // TODO: in tip transactions the destination address must be the input address (of the Tipster or the Reviewers multi-sig address) and the transaction fee must be the parameter.
                var destination = BitcoinAddress.Create(request.DestinationAddress, this.network).ScriptPubKey;
                var context = new TransactionBuildContext(
                    new WalletAccountReference(request.WalletName, request.AccountName),
                    new[] { new Recipient { Amount = new Money(500, MoneyUnit.Satoshi), ScriptPubKey = destination } }.ToList(),
                    request.Password)
                {
                    FeeType = FeeType.Low,
                    MinConfirmations = 0,
                    Shuffle = false,
                    Message = request.Message,
                    MessageRecipient = request.DestinationAddress,
                    EncryptMessage = request.EncryptMessage
                };

                var transactionResult = this.walletTransactionHandler.BuildTransaction(context);

                var model = new WalletBuildTransactionModel
                {
                    Hex = transactionResult.ToHex(),
                    Fee = context.TransactionFee,
                    TransactionId = transactionResult.GetHash()
                };

                return this.Json(model);
            }
            catch (Exception e)
            {
                this.logger.LogError("Exception occurred: {0}", e.ToString());
                return ErrorHelpers.BuildErrorResponse(HttpStatusCode.BadRequest, e.Message, e.ToString());
            }
        }

        /// <summary>
        /// Sends a tip transaction.
        /// </summary>
        /// <param name="request">The hex representing the transaction.</param>
        /// <returns></returns>
        [Route("send-tip-transaction")]
        [HttpPost]
        public IActionResult SendTipTransactionAsync([FromBody] SendTipTransactionRequest request)
        {
            Guard.NotNull(request, nameof(request));

            // checks the request is valid
            if (!this.ModelState.IsValid)
            {
                return BuildErrorResponse(this.ModelState);
            }

            if (!this.connectionManager.ConnectedNodes.Any())
                throw new WalletException("Can't send transaction: sending transaction requires at least one connection!");

            try
            {
                var transaction = new Transaction(request.Hex);

                WalletSendTransactionModel model = new WalletSendTransactionModel
                {
                    TransactionId = transaction.GetHash(),
                    Outputs = new List<TransactionOutputModel>()
                };

                foreach (var output in transaction.Outputs)
                {
                    if (TxMessageTemplate.Instance.CheckScriptPubKey(output.ScriptPubKey))
                    {
                        model.Outputs.Add(new TransactionOutputModel
                        {
                            Address = "N/A - Message: " + TxMessageTemplate.Instance.GetMessage(output.ScriptPubKey).Text,
                            Amount = output.Value,                           
                        });
                    }
                    else
                    {
                        model.Outputs.Add(new TransactionOutputModel
                        {
                            Address = output.ScriptPubKey.GetDestinationAddress(this.network).ToString(),
                            Amount = output.Value,
                        });
                    }
                }

                this.walletManager.ProcessTransaction(transaction, null, null, false);

                this.broadcasterManager.BroadcastTransactionAsync(transaction).GetAwaiter().GetResult();

                return this.Json(model);
            }
            catch (Exception e)
            {
                this.logger.LogError("Exception occurred: {0}", e.ToString());
                return ErrorHelpers.BuildErrorResponse(HttpStatusCode.BadRequest, e.Message, e.ToString());
            }
        }

        [Route("get-tip-messages")]
        [HttpPost]
        public IActionResult GetTipMessagesAsync([FromBody] GetTipMessagesRequest request)
        {
            Guard.NotNull(request, nameof(request));
            
            // checks the request is valid
            if (!this.ModelState.IsValid)
            {
                return BuildErrorResponse(this.ModelState);
            }

            try
            {
                var walletManager = (WalletManager)this.walletManager;
                int requestedBlockHeight = Int32.Parse(request.BlockHeight);

                var messages = walletManager.TxMessages.Values.Where(msg => msg.BlockHeight >= requestedBlockHeight);

                WalletGetMessagesModel model = new WalletGetMessagesModel
                {
                    MinimumBlockHeight = requestedBlockHeight,
                    Messages = new List<TxMessageModel>()
                };

                foreach (var message in messages)
                {
                    model.Messages.Add(new TxMessageModel
                    {
                        IsPropagated = message.IsPropagated,
                        BlockHeight = message.BlockHeight,
                        TransactionHashHex = message.TransactionHashHex,
                        MessageOutputIndex = message.MessageOutputIndex,
                        TransactionHex = message.TransactionHex
                    });
                }

                return this.Json(model);
            }
            catch (Exception e)
            {
                this.logger.LogError("Exception occurred: {0}", e.ToString());
                return ErrorHelpers.BuildErrorResponse(HttpStatusCode.BadRequest, e.Message, e.ToString());
            }
        }

        [Route("create-public-reviewer-address")]
        [HttpPost]
        public IActionResult CreatePublicReviewerAddressAsync([FromBody] CreateReviewerAddressRequest request)
        {
            Guard.NotNull(request, nameof(request));

            // checks the request is valid
            if (!this.ModelState.IsValid)
            {
                return BuildErrorResponse(this.ModelState);
            }

            try
            {
                // calculate the Manager password hash
                byte[] binaryPassword = System.Text.Encoding.ASCII.GetBytes(request.RsaPassword);

                Org.BouncyCastle.Crypto.Digests.Sha512Digest sha = new Org.BouncyCastle.Crypto.Digests.Sha512Digest();
                sha.BlockUpdate(binaryPassword, 0, binaryPassword.Length);

                byte[] shaOutput = new byte[512 / 8];
                sha.DoFinal(shaOutput, 0);

                NBitcoin.DataEncoders.HexEncoder he = new NBitcoin.DataEncoders.HexEncoder();
                string rsaPasswordHashHex = he.EncodeData(shaOutput);

                // create the multisig address
                PubKey[] groupMemberKeys = request.SignaturePubKeys.Select(pubKeyHex => new PubKey(pubKeyHex)).ToArray();

                var scriptPubKey = PayToMultiSigTemplate
                    .Instance
                    .GenerateScriptPubKey(request.RequeiredSignatureCount, groupMemberKeys);


                // generate the RSA keypair for the address
                AsymmetricCipherKeyPair rsaKeyPair = GetRSAKeyPairFromSeed(request.RsaPassword + scriptPubKey.Hash.GetAddress(this.network).ToString());

                RsaKeyParameters rsaPublicKey = rsaKeyPair.Public as RsaKeyParameters;
                RsaPublicKey pbk = new RsaPublicKey()
                {
                    Exponent = rsaPublicKey.Exponent.ToByteArrayUnsigned(),
                    Modulus = rsaPublicKey.Modulus.ToByteArrayUnsigned()
                };

                RsaPrivateCrtKeyParameters rsaPrivateKey = rsaKeyPair.Private as RsaPrivateCrtKeyParameters;
                RsaPrivateKey prk = new RsaPrivateKey()
                {
                    DP = rsaPrivateKey.DP.ToByteArrayUnsigned(),
                    DQ = rsaPrivateKey.DQ.ToByteArrayUnsigned(),
                    Exponent = rsaPrivateKey.Exponent.ToByteArrayUnsigned(),
                    Modulus = rsaPrivateKey.Modulus.ToByteArrayUnsigned(),
                    P = rsaPrivateKey.P.ToByteArrayUnsigned(),
                    PublicExponent = rsaPrivateKey.PublicExponent.ToByteArrayUnsigned(),
                    Q = rsaPrivateKey.Q.ToByteArrayUnsigned(),
                    QInv = rsaPrivateKey.QInv.ToByteArrayUnsigned()
                };

                // return all the information we have
                PublicReviewerAddressModel model = new PublicReviewerAddressModel
                {
                    Network = this.network.ToString(),
                    Address = scriptPubKey.Hash.GetAddress(this.network).ToString(),
                    PublicName = request.PublicName,
                    GroupName = request.GroupName,
                    ValidFrom = request.ValidFrom.HasValue ? request.ValidFrom.Value : 0,
                    ValidUntil = request.ValidUntil.HasValue && (request.ValidUntil.Value != 0) ? request.ValidUntil.Value : Int32.MaxValue,
                    RsaPublicKeyHex = pbk.ToHex(),
                    RsaPrivateKeyHex = prk.ToHex(),
                    RsaPasswordHashHex = rsaPasswordHashHex
                };

                ((WalletManager)this.walletManager).AddReviewerAddressToReviewerStore(model);

                return this.Json(model);
            }
            catch (Exception e)
            {
                this.logger.LogError("Exception occurred: {0}", e.ToString());
                return ErrorHelpers.BuildErrorResponse(HttpStatusCode.BadRequest, e.Message, e.ToString());
            }
        }

        [Route("list-public-reviewer-addresses")]
        [HttpPost]
        public IActionResult ListPublicReviewerAddressesAsync([FromBody] ListReviewerAddressesRequest request)
        {
            Guard.NotNull(request, nameof(request));

            // checks the request is valid
            if (!this.ModelState.IsValid)
            {
                return BuildErrorResponse(this.ModelState);
            }

            try
            {
                var walletManager = (WalletManager)this.walletManager;
                int blockHeight = request.ValidAtBlockHeight;

                var reviewerAddresses = walletManager.ReviewerAddresses.Values.Where(address => true);

                if (!String.IsNullOrWhiteSpace(request.GroupId))
                {
                    reviewerAddresses = reviewerAddresses.Where(address => address.GroupId == request.GroupId);
                }

                if (!String.IsNullOrWhiteSpace(request.PublicNameFragment))
                {
                    reviewerAddresses = reviewerAddresses.Where(address => address.PublicName.ToLowerInvariant().Contains(request.PublicNameFragment.ToLowerInvariant()));
                }

                if (request.ValidAtBlockHeight > 0)
                {
                    reviewerAddresses = reviewerAddresses.Where(address => (address.ValidFrom <= request.ValidAtBlockHeight) && (address.ValidUntil >= request.ValidAtBlockHeight));
                }

                ListPublicReviewerAddressesModel model = new ListPublicReviewerAddressesModel
                {
                    Addresses = reviewerAddresses.ToArray()
                };

                return this.Json(model);
            }
            catch (Exception e)
            {
                this.logger.LogError("Exception occurred: {0}", e.ToString());
                return ErrorHelpers.BuildErrorResponse(HttpStatusCode.BadRequest, e.Message, e.ToString());
            }
        }



        public static AsymmetricCipherKeyPair GetRSAKeyPairFromSeed(string rsaSeed, int rsaKeySize = 4096, CoinType coinType = CoinType.Stratis)
        {
            byte[] binaryRsaSeed = System.Text.Encoding.ASCII.GetBytes(rsaSeed);

            // apply SHAKE-256
            var digest = new Org.BouncyCastle.Crypto.Digests.SkeinDigest(256, 4096);
            int digestSize = digest.GetDigestSize();
            digest.BlockUpdate(binaryRsaSeed, 0, binaryRsaSeed.Length);

            byte[] rsaSeedDigest = new byte[4096 / 8];
            digest.DoFinal(rsaSeedDigest, 0);


            var randomSeedGenerator = System.Security.Cryptography.RandomNumberGenerator.Create();
            byte[] seed = new byte[rsaKeySize / 8];
            randomSeedGenerator.GetBytes(seed);

            VmpcRandomGenerator randomGenerator = new VmpcRandomGenerator();
            randomGenerator.AddSeedMaterial(seed);

            //CryptoApiRandomGenerator randomGenerator = new CryptoApiRandomGenerator();
            var secureRandom = new SecureRandom(randomGenerator);
            var keyGenerationParameters = new KeyGenerationParameters(secureRandom, rsaKeySize);

            var privateKeyBasedRsaKeyPairGenerator = new SeedBasedDeterministicRsaKeyPairGenerator();
            privateKeyBasedRsaKeyPairGenerator.Init(keyGenerationParameters, rsaSeedDigest);
            var result = privateKeyBasedRsaKeyPairGenerator.GenerateKeyPair();

            return result;
        }

        /// <summary>
        /// Deterministically generates one particular RSA keypair based on a private key
        /// </summary>
        private class SeedBasedDeterministicRsaKeyPairGenerator : RsaKeyPairGenerator
        {
            private static readonly int[] SPECIAL_E_VALUES = new int[] { 3, 5, 17, 257, 65537 };
            private static readonly int SPECIAL_E_HIGHEST = SPECIAL_E_VALUES[SPECIAL_E_VALUES.Length - 1];
            private static readonly int SPECIAL_E_BITS = BigInteger.ValueOf(SPECIAL_E_HIGHEST).BitLength;

            private byte[] generatorKey;

            public void Init(KeyGenerationParameters parameters, byte[] seed)
            {
                this.generatorKey = seed;
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
                    int pBitLength = (strength + 1) / 2;
                    int qBitLength = strength - pBitLength;
                    int mindiffbits = strength / 3;
                    int minWeight = strength >> 2;

                    if ((pBitLength % 8 != 0) || (qBitLength % 8 != 0))
                    {
                        throw new Exception($"The bitlength of both p and q must be a multilple of 8.");
                    }

                    byte[] pBytes = this.generatorKey.Take(pBitLength / 8).ToArray();
                    BigInteger pStartValue = new BigInteger(+1, pBytes);

                    byte[] qBytes = this.generatorKey.Skip(Math.Max(0, this.generatorKey.Count() - (qBitLength / 8))).ToArray();
                    BigInteger qStartValue = new BigInteger(+1, qBytes);

                    BigInteger e = this.parameters.PublicExponent;

                    // TODO Consider generating safe primes for p, q (see DHParametersHelper.generateSafePrimes)
                    // (then p-1 and q-1 will not consist of only small factors - see "Pollard's algorithm")

                    int pIndex = 1;
                    int qIndex = 0;
                    //BigInteger p = ChooseRandomPrime(pBitlength, e);
                    BigInteger p = ChooseNthPrime(pStartValue, e, pIndex, pBitLength);
                    BigInteger q, n;
                    q = qStartValue;

                    //
                    // generate a modulus of the required length
                    //
                    for (; ; )
                    {
                        qIndex++;
                        q = ChooseNthPrime(qStartValue, e, qIndex, qBitLength);

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
                            pIndex++;
                            p = ChooseNthPrime(pStartValue, e, pIndex, pBitLength);
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

                    if (d.BitLength <= qBitLength)
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
            protected BigInteger ChooseNthPrime(BigInteger startValue, BigInteger e, int n, int bitLength)
            {
                bool eIsKnownOddPrime = (e.BitLength <= SPECIAL_E_BITS) && Arrays.Contains(SPECIAL_E_VALUES, e.IntValue);

                BigInteger p = new BigInteger(startValue.ToByteArray());
                Console.WriteLine($" -NOTE- We are looking to the {n}. lower prime starting from {p.ToString()} with {bitLength} bits.");

                int counter = 0;

                while (true)
                {
                    if (p.BitLength < bitLength)
                    {
                        Console.WriteLine($" -NOTE- The bitrate dropped from {bitLength} to {p.BitLength}, so we reset our p value.");

                        p = new BigInteger(+1, Enumerable.Repeat((byte)0xFF, bitLength / 8).ToArray());
                    }

                    // Subtract one from p in an efficient way
                    int lsb = p.GetLowestSetBit();
                    p = p.ClearBit(lsb);
                    for (int i=0; i<lsb; i++)
                    {
                        p = p.SetBit(i);
                    }

                    counter++;
                    if (counter % 1500 == 0)
                    {
                        Console.WriteLine($" -NOTE- The number we are testing right now is {p.ToString()}, {n} more prime(s) to go.");
                        counter = 0;
                    }

                    if (!p.TestBit(0)) continue;

                    if (p.Mod(e).Equals(One))
                        continue;

                    if (!p.IsProbablePrime(this.parameters.Certainty))
                        continue;

                    if (!eIsKnownOddPrime && !e.Gcd(p.Subtract(One)).Equals(One))
                        continue;

                    Console.WriteLine($" -NOTE- Potential prime '{p.ToString()}' was found. {n-1} more to go.");

                    // p is a prime
                    n--;
                    if (n <= 0) break;
                }

                return p;
            }
        }

    }
}
