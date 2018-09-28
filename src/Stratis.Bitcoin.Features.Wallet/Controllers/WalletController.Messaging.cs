using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security;
using System.Text;
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
using Stratis.Bitcoin.Utilities.ModelStateErrors;
using Newtonsoft.Json;

namespace Stratis.Bitcoin.Features.Wallet.Controllers
{
    public partial class WalletController : Controller
    {
        /// <summary>
        /// Deserializes a transaction hex into json format
        /// </summary>
        /// <param name="request">The transaction parameters.</param>
        /// <returns>The estimated fee for the transaction.</returns>
        [Route("deserialize-transaction")]
        [HttpPost]
        public IActionResult Deserialize([FromBody] DeserializeTransactionRequest request)
        {
            Guard.NotNull(request, nameof(request));

            // checks the request is valid
            if (!this.ModelState.IsValid)
            {
                return ModelStateErrors.BuildErrorResponse(this.ModelState);
            }

            try
            {
                Transaction transaction = this.network.CreateTransaction(request.Hex);
                return Content(transaction.ToString(this.network));
            }
            catch (Exception e)
            {
                this.logger.LogError("Exception occurred: {0}", e.ToString());
                return ErrorHelpers.BuildErrorResponse(HttpStatusCode.BadRequest, e.Message, e.ToString());
            }
        }



        /// <summary>
        /// Gets a wanted system message (WSM) fee estimate.
        /// Fee can be estimated by creating a <see cref="TransactionBuildContext"/> with no password
        /// and then building the tip transaction and retrieving the fee from the context.
        /// </summary>
        /// <param name="request">The transaction parameters.</param>
        /// <returns>The estimated fee for the transaction.</returns>
        [Route("estimate-wanted-system-message-fee")]
        [HttpGet]
        public IActionResult EstimateWantedSystemMessageFee([FromQuery] EstimateWantedSystemMessageFeeRequest request)
        {
            Guard.NotNull(request, nameof(request));

            // checks the request is valid
            if (!this.ModelState.IsValid)
            {
                return ModelStateErrors.BuildErrorResponse(this.ModelState);
            }

            try
            {
                var destination = BitcoinAddress.Create(request.DestinationAddress, this.network).ScriptPubKey;
                var context = new TransactionBuildContext(this.network)
                { 
                    AccountReference = new WalletAccountReference(request.WalletName, request.AccountName),
                    Recipients = new[] { new Recipient { Amount = new Money(500, this.network.MoneyUnits.AtomicUnit), ScriptPubKey = destination } }.ToList(),
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
        /// Builds a _unsigned_ wanted system message (WSM) transaction. If the tip trancation is paid by the Tipster, the message should not be encrypted. If the tip tranaction is paid by the Reviewers, the message should be encrypted with their keys.
        /// </summary>
        /// <param name="request">The transaction parameters.</param>
        /// <returns>All the details of the transaction, including the hex used to execute it.</returns>
        [Route("build-wanted-system-message")]
        [HttpPost]
        public IActionResult BuildWantedSystemMessage([FromBody] BuildWantedSystemMessageRequest request)
        {
            Guard.NotNull(request, nameof(request));

            // checks the request is valid
            if (!this.ModelState.IsValid)
            {
                return ModelStateErrors.BuildErrorResponse(this.ModelState);
            }

            try
            {
                // in wanted message transactions the payer address must be the input address (of the Tipster or the Reviewers multi-sig address) and the transaction fee must be the parameter.
                var payer = BitcoinAddress.Create(request.PayerAddress, this.network);
                var destination = BitcoinAddress.Create(request.DestinationAddress, this.network).ScriptPubKey;
                var context = new TransactionBuildContext(this.network)
                {
                    AccountReference = new WalletAccountReference(request.WalletName, request.AccountName),
                    Recipients = new[] { new Recipient { Amount = new Money(500, this.network.MoneyUnits.AtomicUnit), ScriptPubKey = destination } }.ToList(),
                    WalletPassword = request.WalletPassword,
                    FeeType = FeeType.Low,
                    MinConfirmations = 0,
                    Shuffle = false,
                    PayerAddress = payer,
                    Message = request.Message,
                    MessageRecipient = request.DestinationAddress,
                    EncryptMessage = request.EncryptMessage,
                    Sign = false
                };

                var transactionResult = this.walletTransactionHandler.BuildWantedSystemMessage(context);

                var model = new WalletBuildTransactionModel
                {
                    TransactionId = transactionResult.GetHash(),
                    Hex = transactionResult.ToHex(),
                    Fee = context.TransactionFee
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
        /// Sends a wanted system message (WSM) transaction.
        /// </summary>
        /// <param name="request">The hex representing the transaction.</param>
        /// <returns></returns>
        [Route("send-wanted-system-message")]
        [HttpPost]
        public IActionResult SendWantedSystemMessageAsync([FromBody] SendWantedSystemMessageRequest request)
        {
            Guard.NotNull(request, nameof(request));

            // checks the request is valid
            if (!this.ModelState.IsValid)
            {
                return ModelStateErrors.BuildErrorResponse(this.ModelState);
            }

            if (!this.connectionManager.ConnectedPeers.Any())
                throw new WalletException("Can't send transaction: sending transaction requires at least one connection!");

            try
            {
                Transaction transaction = this.network.CreateTransaction(request.Hex);

                WalletSendTransactionModel model = new WalletSendTransactionModel
                {
                    TransactionId = transaction.GetHash(),
                    Outputs = new List<TransactionOutputModel>()
                };

                foreach (var output in transaction.Outputs)
                {
                    if (WantedSystemMessageTemplate.Instance.CheckScriptPubKey(output.ScriptPubKey))
                    {
                        model.Outputs.Add(new TransactionOutputModel
                        {
                            Address = $"N/A (Wanted System Message)",
                            Amount = output.Value
                        });
                    }
                    else
                    {
                        model.Outputs.Add(new TransactionOutputModel
                        {
                            Address = output.ScriptPubKey.GetDestinationAddress(this.network).ToString(),
                            Amount = output.Value
                        });
                    }
                }

                if (transaction.Inputs.All(tri => String.IsNullOrEmpty(tri.ScriptSig.ToString())))
                {
                    throw new Exception("This transcation is not signed. In order to publish a transaction on the network, it must be fully signed first.");
                }

                if (transaction.Inputs.Any(tri => String.IsNullOrEmpty(tri.ScriptSig.ToString())))
                {
                    throw new Exception("This transcation is only partially signed. In order to publish a transaction on the network, it must be fully signed first.");
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

        /// <summary>
        /// Gets all the wanted system messages (WSMs) from the local store (messages.json)
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        [Route("list-wanted-system-messages")]
        [HttpPost]
        public IActionResult ListWantedSystemMessagesAsync([FromBody] ListWantedSystemMessagesRequest request)
        {
            Guard.NotNull(request, nameof(request));
            
            // checks the request is valid
            if (!this.ModelState.IsValid)
            {
                return ModelStateErrors.BuildErrorResponse(this.ModelState);
            }

            try
            {
                var walletManager = (WalletManager)this.walletManager;
                int requestedBlockHeight = String.IsNullOrWhiteSpace(request.BlockHeight) ? 0 : Int32.Parse(request.BlockHeight);

                var messages = walletManager.WantedSystemMessages.Values.Where(msg => (msg.BlockHeight >= requestedBlockHeight) || (requestedBlockHeight == 0));

                ListWantedSystemMessagesModel model = new ListWantedSystemMessagesModel
                {
                    MinimumBlockHeight = requestedBlockHeight,
                    Messages = new List<WantedSystemMessageModel>()
                };

                foreach (var message in messages)
                {
                    model.Messages.Add(new WantedSystemMessageModel
                    {
                        IsPropagated = message.IsPropagated,
                        BlockHeight = message.BlockHeight,
                        TransactionHashHex = message.TransactionHashHex,
                        MessageOutputIndex = message.MessageOutputIndex,
                        TransactionHex = message.TransactionHex,
                        PartiallySignedTransactions = message.PartiallySignedTransactions
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

        /// <summary>
        /// Decrypts a wanted system message (WSMs)
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        [Route("decrypt-wanted-system-message")]
        [HttpPost]
        public IActionResult DecryptWantedSystemMessageAsync([FromBody] DecryptWantedSystemMessageRequest request)
        {
            Guard.NotNull(request, nameof(request));

            // checks the request is valid
            if (!this.ModelState.IsValid)
            {
                return ModelStateErrors.BuildErrorResponse(this.ModelState);
            }

            try
            {
                Script scriptPubKey = Transaction.Parse(request.TransactionHex, RawFormat.Satoshi).Outputs[request.MessageOutputIndex].ScriptPubKey;
                RsaPrivateKey rsaPrivateKey = null;
                if (!String.IsNullOrEmpty(request.RsaPrivateKeyHex))
                {
                    try
                    {
                        rsaPrivateKey = RsaPrivateKey.FromHex(request.RsaPrivateKeyHex);
                    }
                    catch
                    {
                        throw new Exception("The RSA private key you provided was not in the correct form.");
                    }
                }

                NBitcoin.Messaging.WantedSystemMessage sm = WantedSystemMessageTemplate.Instance.GetWantedSystemMessage(scriptPubKey, rsaPrivateKey);

                var model = new DecryptedWantedSystemMessageModel
                {
                    Version = sm.Version,
                    Compression = sm.Compression.ToString(),
                    ChecksumType = sm.ChecksumType.ToString(),
                    Encryption = sm.Encryption.ToString(),
                    Metadata = sm.Metadata.ToString(),
                    Text = sm.Text
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
        /// Create a new reviewer addresses (this can take up to a minute)
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        [Route("create-reviewer-address")]
        [HttpPost]
        public IActionResult CreateReviewerAddressAsync([FromBody] CreateReviewerAddressRequest request)
        {
            Guard.NotNull(request, nameof(request));

            // checks the request is valid
            if (!this.ModelState.IsValid)
            {
                return ModelStateErrors.BuildErrorResponse(this.ModelState);
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

                PublicReviewerAddressModel model = new PublicReviewerAddressModel
                {
                    PublicApiUrl = request.PublicApiUrl
                };

                // check if the API is reachable and the address can be added to the watch list
                Uri apiRequestUri = new Uri(new Uri(model.PublicApiUrl), $"/api/WatchOnlyWallet/watch?address={scriptPubKey.Hash.GetAddress(this.network).ToString()}");
                try
                {
                    HttpWebRequest apiRequest = (HttpWebRequest)WebRequest.Create(apiRequestUri);

                    ASCIIEncoding encoding = new ASCIIEncoding();
                    string postData = "";
                    byte[] data = encoding.GetBytes(postData);

                    apiRequest.Method = "POST";
                    apiRequest.ContentType = "application/x-www-form-urlencoded";
                    apiRequest.ContentLength = data.Length;

                    using (Stream stream = apiRequest.GetRequestStream())
                    {
                        stream.Write(data, 0, data.Length);
                    }

                    HttpWebResponse apiResponse = (HttpWebResponse)apiRequest.GetResponse();

                    string responseString = new StreamReader(apiResponse.GetResponseStream()).ReadToEnd();

                    if (apiResponse.StatusCode != HttpStatusCode.OK)
                    {
                        throw new Exception($"The API request '{apiRequestUri.ToString()}' returned the status code '{apiResponse.StatusCode}'.");
                    }
                }
                catch (Exception e)
                {
                    throw new Exception($"The API request '{apiRequestUri.ToString()}' returned an error '{e.Message}'.");
                }


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
                model = new PublicReviewerAddressModel
                {
                    Network = this.network.ToString(),
                    Address = scriptPubKey.Hash.GetAddress(this.network).ToString(),
                    PublicName = request.PublicName,
                    GroupName = request.GroupName,
                    ValidFrom = request.ValidFrom.ToString("o"),
                    ValidUntil = request.ValidUntil.ToString("o"),
                    ScriptPubKeyHex = scriptPubKey.ToHex(),
                    RsaPublicKeyHex = pbk.ToHex(),
                    RsaPrivateKeyHex = prk.ToHex(),
                    RsaPasswordHashHex = rsaPasswordHashHex,
                    PublicApiUrl = request.PublicApiUrl
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

        /// <summary>
        /// Lists all reviewer addresses from the local store (reviewers.json)
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        [Route("list-reviewer-addresses")]
        [HttpPost]
        public IActionResult ListReviewerAddressesAsync([FromBody] ListReviewerAddressesRequest request)
        {
            Guard.NotNull(request, nameof(request));

            // checks the request is valid
            if (!this.ModelState.IsValid)
            {
                return ModelStateErrors.BuildErrorResponse(this.ModelState);
            }

            try
            {
                var walletManager = (WalletManager)this.walletManager;

                var reviewerAddresses = walletManager.ReviewerAddresses.Values.Where(address => true);

                if (!String.IsNullOrWhiteSpace(request.GroupId))
                {
                    reviewerAddresses = reviewerAddresses.Where(address => address.GroupId == request.GroupId);
                }

                if (!String.IsNullOrWhiteSpace(request.PublicNameFragment))
                {
                    reviewerAddresses = reviewerAddresses.Where(address => address.PublicName.ToLowerInvariant().Contains(request.PublicNameFragment.ToLowerInvariant()));
                }

                if (request.ValidAt.HasValue)
                {
                    reviewerAddresses = reviewerAddresses.Where(address => (DateTimeOffset.Parse(address.ValidFrom) <= request.ValidAt.Value) && (DateTimeOffset.Parse(address.ValidUntil) >= request.ValidAt.Value));
                }

                ListPublicReviewerAddressesModel model = new ListPublicReviewerAddressesModel
                {
                    Addresses = reviewerAddresses.OrderByDescending(a => a.ValidFrom).OrderByDescending(a => a.ValidUntil).ToArray()
                };

                // remove the sensitive information
                foreach (PublicReviewerAddressModel address in model.Addresses)
                {
                    address.RsaPrivateKeyHex = "";
                    address.RsaPasswordHashHex = "";
                }

                return this.Json(model);
            }
            catch (Exception e)
            {
                this.logger.LogError("Exception occurred: {0}", e.ToString());
                return ErrorHelpers.BuildErrorResponse(HttpStatusCode.BadRequest, e.Message, e.ToString());
            }
        }

        /// <summary>
        /// Sign a wanted system messages (WSMs). This method should be used with special attention because it transfers sensitive information. It can be used to test partially signed WSMs.
        /// If the signing key is not provided then the method is safe and the node will try to sign the message with its own wallet's private keys.
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        [Route("sign-wanted-system-message")]
        [HttpPost]
        public IActionResult SignWantedSystemMessageAsync([FromBody] SignWantedSystemMessageRequest request)
        {
            Guard.NotNull(request, nameof(request));

            // checks the request is valid
            if (!this.ModelState.IsValid)
            {
                return ModelStateErrors.BuildErrorResponse(this.ModelState);
            }

            try
            {
                // parse the transaction
                Transaction tx = Transaction.Parse(request.TransactionHex, RawFormat.Satoshi);

                // check if we have the message transaction in our message store
                WalletManager wm = this.walletManager as WalletManager;
                if (!wm.WantedSystemMessages.Any(t => t.Key == tx.GetHash()))
                {
                    throw new Exception($"The transcation with hash '{tx.GetHash()}' is not in the message store. You must upload it first by using the upload-wanted-system-message API.");
                }
                //WantedSystemMessageModel wantedMessage = wm.WantedSystemMessages.First(t => t.Key == tx.GetHash()).Value;

                // get the signing keys
                List<BitcoinExtKey> privateKeys = new List<BitcoinExtKey>();
                if (!String.IsNullOrWhiteSpace(request.SigningKey))
                {
                    // parse request.SigningKey into a Bitcoin Private Key
                    try
                    {
                        privateKeys.Add(new BitcoinExtKey(request.SigningKey));
                    }
                    catch
                    {
                        throw new Exception($"The signing key you provided is not in a valid format.");
                    }
                } else
                {
                    throw new Exception($"You must provide a signing key in order to sign the message.");

                    // TODO: add our own private keys                    
                }

                // sign the transaction with the key
                var reviewerAddress = wm.ReviewerAddresses[request.ReviewerAddress];
                if (reviewerAddress == null)
                {                    
                    throw new Exception($"The reviewer '{request.ReviewerAddress}' was not found in the address book.");
                }

                TransactionBuilder tb = new TransactionBuilder(this.network);
                tb.AddCoins((this.walletTransactionHandler as WalletTransactionHandler).GetCoinsForReviewersAddress(reviewerAddress));
                tb.AddCoins(tx);
                Transaction signedTx = tb.AddKeys(privateKeys.ToArray()).SignTransaction(tx);

                if (signedTx.GetHash() == tx.GetHash())
                {
                    throw new Exception($"The signing key you provided is not associated with the message or it is already signed with that key.");
                }

                // return the (partially) signed transaction
                SignWantedSystemMessageModel model = new SignWantedSystemMessageModel
                {
                    TransactionHex = signedTx.ToHex(),
                    WasSigned = request.TransactionHex != signedTx.ToHex()
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
        /// Upload a wanted system messages (WSMs) to the node's local store (messages.json). It is useful for uploading the partially signed WSMs, so that the node can combine them.
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        [Route("upload-wanted-system-message")]
        [HttpPost]
        public IActionResult UploadWantedSystemMessageAsync([FromBody] UploadWantedSystemMessageRequest request)
        {
            Guard.NotNull(request, nameof(request));

            // checks the request is valid
            if (!this.ModelState.IsValid)
            {
                return ModelStateErrors.BuildErrorResponse(this.ModelState);
            }

            try
            {
                Transaction transaction = this.network.CreateTransaction(request.TransactionHex);

                var wantedMessageOuts = transaction.Outputs.Where(txOut => WantedSystemMessageTemplate.Instance.CheckScriptPubKey(txOut.ScriptPubKey));

                if (wantedMessageOuts.Count() == 0)
                {
                    throw new Exception("The transaction you provided doesn't contain any Wanted System Messages.");
                }

                var wm = this.walletManager as WalletManager;

                WantedSystemMessageModel wsmm = null;

                // let's make sure that the transaction is put into the message store
                wsmm = wm.AddWantedSystemMessageToMessageStore(transaction);

                // add the partially signed transaction to the message store
                // TODO: do not limit this check to the first input
                if (transaction.Inputs[0].ScriptSig.Length > 0)
                {
                    wsmm = wm.AddPartiallySignedTxToMessageStore(transaction);
                }


                // get the reviewer's address details
                var reviewerAddress = wm.ReviewerAddresses[request.ReviewerAddress];
                if (reviewerAddress == null)
                {
                    throw new Exception($"The reviewer '{request.ReviewerAddress}' was not found in the address book.");
                }
                var multiSigParams = PayToMultiSigTemplate.Instance.ExtractScriptPubKeyParameters(reviewerAddress.ScriptPubKey);

                // try to combine the partially signed signatures                
                TransactionBuilder tb = new TransactionBuilder(this.network);
                tb.AddCoins((this.walletTransactionHandler as WalletTransactionHandler).GetCoinsForReviewersAddress(reviewerAddress));

                var fullySignedTx = tb.CombineSignatures(wsmm.PartiallySignedTransactions.Select(stx => Transaction.Parse(stx.TransactionHex, RawFormat.Satoshi)).ToArray());
                if (fullySignedTx != null)
                {
                    var checkResults = fullySignedTx.Check();

                    // TODO: do not limit this check to the first input
                    string[] signatures = fullySignedTx.Inputs[0].ScriptSig.ToString().Split(' ');
                    int signatureCount = signatures.Count(s => s != "0");

                    if ((checkResults != TransactionCheckResult.Success) || (signatureCount < multiSigParams.SignatureCount))
                    {
                        fullySignedTx = null;
                    }
                }

                // return the fully signed transaction if available
                UploadWantedSystemMessageModel model = new UploadWantedSystemMessageModel
                {
                    WantedSystemMessage = wsmm,
                    FullySignedTransactionHex = fullySignedTx == null ? "" : fullySignedTx.ToHex()
                };

                return this.Json(model);
            }
            catch (Exception e)
            {
                this.logger.LogError("Exception occurred: {0}", e.ToString());
                return ErrorHelpers.BuildErrorResponse(HttpStatusCode.BadRequest, e.Message, e.ToString());
            }
        }


        [Route("list-account-addresses-with-keys")]
        [HttpPost]
        public IActionResult ListAccountAddressesWithKeys([FromBody] ListAccountAddressesWithKeysRequest request)
        {
            Guard.NotNull(request, nameof(request));

            // checks the request is valid
            if (!this.ModelState.IsValid)
            {
                return ModelStateErrors.BuildErrorResponse(this.ModelState);
            }

            try
            {
                Wallet wallet = this.walletManager.GetWalletByName(request.WalletName);

                HdAccount account = wallet.GetAccountByCoinType(request.AccountName, this.coinType);

                ListAccountAddressesWithKeysModel model = new ListAccountAddressesWithKeysModel
                {
                    Network = this.network.ToString(),
                    WalletName = wallet.Name,
                    AccountName = account.Name,
                    ExternalAddresses = GetHdAddressModels(wallet, request.WalletPassword, account.ExternalAddresses),
                    InternalAddresses = GetHdAddressModels(wallet, request.WalletPassword, account.InternalAddresses)
                };

                return this.Json(model);
            }
            catch (Exception e)
            {
                this.logger.LogError("Exception occurred: {0}", e.ToString());
                return ErrorHelpers.BuildErrorResponse(HttpStatusCode.BadRequest, e.Message, e.ToString());
            }
        }

        [Route("list-spendable-transaction-outs")]
        [HttpPost]
        public IActionResult ListSpendableTransactionOuts([FromBody] ListSpendableTransactionOutsRequest request)
        {
            Guard.NotNull(request, nameof(request));

            // checks the request is valid
            if (!this.ModelState.IsValid)
            {
                return ModelStateErrors.BuildErrorResponse(this.ModelState);
            }

            try
            {
                string requestWalletName = null;
                string requestAccountName = null;

                if (String.IsNullOrWhiteSpace(request.WalletName) || String.IsNullOrWhiteSpace(request.AccountName))
                {
                    // let's find the proper wallet and account first
                    foreach (var walletName in this.walletManager.GetWalletsNames())
                    {
                        HdAddress address = null;
                        foreach (var hdAccount in this.walletManager.GetWallet(walletName).GetAccountsByCoinType(this.coinType))
                        {
                            address = hdAccount.ExternalAddresses.FirstOrDefault(hdAddress => hdAddress.Address.ToString() == request.Address);
                            if (address == null)
                            {
                                address = hdAccount.InternalAddresses.FirstOrDefault(hdAddress => hdAddress.Address.ToString() == request.Address);
                            }

                            if (address != null)
                            {
                                requestAccountName = hdAccount.Name;
                                break;
                            }
                        }

                        if (requestAccountName != null)
                        {
                            requestWalletName = walletName;
                            break;
                        }
                    }

                    if ((requestWalletName == null) || (requestAccountName == null))
                    {
                        throw new Exception("The address you requested is not in this wallet.");
                    }
                } else
                {
                    requestWalletName = request.WalletName;
                    requestAccountName = request.AccountName;
                }

                WalletAccountReference account = new WalletAccountReference(requestWalletName, requestAccountName);

                List<SpendableTransactionModel> transactionList = new List<SpendableTransactionModel>();
                foreach (var spendableOutput in this.walletManager.GetSpendableTransactionsInAccount(account, request.MinConfirmations).OrderByDescending(a => a.Transaction.Amount))
                {
                    if (spendableOutput.Transaction.Amount == 0) continue;

                    if (!String.IsNullOrWhiteSpace(request.Address) && (spendableOutput.Address.Address.ToString() != request.Address)) continue;

                    transactionList.Add(new SpendableTransactionModel()
                    {
                        Address = spendableOutput.Address.Address.ToString(),
                        TransactionHash = spendableOutput.Transaction.Id,
                        Index = spendableOutput.Transaction.Index,
                        Amount = spendableOutput.Transaction.Amount.Satoshi,
                        ScriptPubKey = spendableOutput.Transaction.ScriptPubKey.ToHex()
                    });
                }

                ListSpendableTransactionsModel model = new ListSpendableTransactionsModel
                {
                    Network = this.network.ToString(),
                    WalletName = account.WalletName,
                    AccountName = account.AccountName,
                    SpendableTransactions = transactionList
                };

                return this.Json(model);
            }
            catch (Exception e)
            {
                this.logger.LogError("Exception occurred: {0}", e.ToString());
                return ErrorHelpers.BuildErrorResponse(HttpStatusCode.BadRequest, e.Message, e.ToString());
            }
        }        

        private ICollection<HdAddressModel> GetHdAddressModels(Wallet wallet, string walletPassword, ICollection<HdAddress> accountAddresses, int count = 3, bool listUsed = false)
        {
            List<HdAddressModel> addressModel = new List<HdAddressModel>();

            foreach (var address in accountAddresses)
            {
                if ((!listUsed) && (address.Transactions.Count > 0)) continue;

                var privateKey = wallet.GetExtendedPrivateKeyForAddress(walletPassword, address);

                addressModel.Add(new HdAddressModel()
                {
                    Address = address.Address,
                    HdPath = address.HdPath,
                    PublicKey = privateKey.PrivateKey.PubKey.ToString(),
                    PublicKeyHash = privateKey.PrivateKey.PubKey.Hash.ToString(),
                    PrivateKeyWif = privateKey.ToString(),
                    TransactionCount = address.Transactions.Count
                });

                if (addressModel.Count >= count) break;
            }

            return addressModel;
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

                    // p should always be higher than q
                    if (pStartValue.CompareTo(qStartValue) < 0)
                    {
                        BigInteger temp = pStartValue;
                        pStartValue = qStartValue;
                        qStartValue = temp;
                    }

                    BigInteger p = ChooseNthPrime(pStartValue, e, +1, pBitLength);
                    BigInteger q = ChooseNthPrime(qStartValue, e, -1, qBitLength);
                    BigInteger n;

                    //
                    // generate a modulus of the required length
                    //
                    bool changeP = false;
                    for (; ; )
                    {                        
                        if (changeP)
                        {
                            p = ChooseNthPrime(p, e, +1, pBitLength);
                        } else
                        {                            
                            q = ChooseNthPrime(q, e, -1, qBitLength);
                        }
                        changeP = !changeP;

                        // p and q should not be too close together (or equal!)
                        BigInteger diff = p.Subtract(q).Abs();
                        if (diff.BitLength < mindiffbits)
                        {
                            Console.WriteLine($" -NOTE- The difference between the two primes are only {diff.BitLength} and the requirement is {mindiffbits}. Retrying...");

                            continue;
                        }

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
                            Console.WriteLine($" -NOTE- The modulus bit strength is {n.BitLength} and the requirement is {strength}. Retrying...");

                            if (!p.TestBit(p.BitLength - 2))
                            {
                                p = p.SetBit(p.BitLength - 2);
                                changeP = true;
                            }
                            else if (!q.TestBit(q.BitLength - 2))
                            {
                                q = q.SetBit(q.BitLength - 2);
                                changeP = false;
                            }

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
                            Console.WriteLine($" -NOTE- The NAF weight is {WNafUtilities.GetNafWeight(n)} and the requirement is {minWeight}. Retrying...");

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

                while (true)
                {
                    if (p.BitLength > bitLength)
                    {
                        Console.WriteLine($" -NOTE- The bitrate raised from {bitLength} to {p.BitLength}, so we reset our p value.");
                        p = p.ClearBit(bitLength);
                    }

                    if (p.BitLength < bitLength)
                    {
                        Console.WriteLine($" -NOTE- The bitrate dropped from {bitLength} to {p.BitLength}, so we reset our p value.");
                        p = p.SetBit(bitLength - 1);
                    }



                    if (n > 0)
                    {
                        // Add one to p in an efficient way
                        for (int i = 0; i <= p.BitLength; i++)
                        {
                            if (!p.TestBit(i))
                            {
                                p = p.SetBit(i);
                                break;
                            }
                            p = p.ClearBit(i);
                        }
                    }
                    else if (n < 0)
                    {
                        // Subtract one from p in an efficient way
                        int lsb = p.GetLowestSetBit();
                        p = p.ClearBit(lsb);
                        for (int i = 0; i < lsb; i++)
                        {
                            p = p.SetBit(i);
                        }
                    }

                    if (!p.TestBit(0)) continue;

                    if (p.Mod(e).Equals(One))
                        continue;

                    if (!p.IsProbablePrime(this.parameters.Certainty))
                        continue;

                    if (!eIsKnownOddPrime && !e.Gcd(p.Subtract(One)).Equals(One))
                        continue;

                    // p is a prime
                    if (n > 0)
                    {
                        n--;
                    } else if (n < 0) 
                    {
                        n++;
                    }

                    if (n == 0) break;
                }

                return p;
            }
        }

    }
}
