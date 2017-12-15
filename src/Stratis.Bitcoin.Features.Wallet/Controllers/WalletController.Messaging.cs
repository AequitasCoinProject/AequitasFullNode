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
        /// Builds a tip transaction.
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
    }
}
