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

            if (!this.connectionManager.ConnectedPeers.Any())
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
                            Address = "N/A - Message: " + TxMessageTemplate.Instance.GetMessage(output.ScriptPubKey),
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
                        TransactionHash = message.TransactionHashHex,
                        MessageOutputIndex = message.OutputIndex,
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
                PubKey[] groupMemberKeys = request.SignaturePubKeys.Select(pubKeyHex => new PubKey(pubKeyHex)).ToArray();

                var scriptPubKey = PayToMultiSigTemplate
                    .Instance
                    .GenerateScriptPubKey(request.RequeiredSignatureCount, groupMemberKeys);

                // TODO: create a group for it if it doesn't exists

                // TODO: save the reviewer addresses file

                PublicReviewerAddressModel model = new PublicReviewerAddressModel
                {
                    Network = this.network.ToString(),
                    Address = scriptPubKey.Hash.GetAddress(this.network).ToString()
                };

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
                ListPublicReviewerAddressesModel model = new ListPublicReviewerAddressesModel
                {
                };

                return this.Json(model);
            }
            catch (Exception e)
            {
                this.logger.LogError("Exception occurred: {0}", e.ToString());
                return ErrorHelpers.BuildErrorResponse(HttpStatusCode.BadRequest, e.Message, e.ToString());
            }
        }

    }
}
