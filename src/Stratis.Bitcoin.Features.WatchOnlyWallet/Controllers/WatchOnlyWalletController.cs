using System;
using System.Collections.Generic;
using System.Net;
using System.Linq;
using Microsoft.AspNetCore.Mvc;
using NBitcoin;
using Stratis.Bitcoin.Controllers.Models;
using Stratis.Bitcoin.Features.WatchOnlyWallet.Models;
using Stratis.Bitcoin.Utilities.JsonErrors;
using Stratis.Bitcoin.Utilities;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.Extensions.Logging;
using NBitcoin;

namespace Stratis.Bitcoin.Features.WatchOnlyWallet.Controllers
{
    /// <summary>
    /// Controller providing operations on a watch-only wallet.
    /// </summary>
    [Route("api/[controller]")]
    public class WatchOnlyWalletController : Controller
    {
        /// <summary> The watch-only wallet manager. </summary>
        private readonly IWatchOnlyWalletManager watchOnlyWalletManager;

        /// <summary>Instance logger.</summary>
        private readonly ILogger logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="WatchOnlyWalletController"/> class.
        /// </summary>
        /// <param name="watchOnlyWalletManager">The watch-only wallet manager.</param>
        public WatchOnlyWalletController(
            ILoggerFactory loggerFactory, 
            IWatchOnlyWalletManager watchOnlyWalletManager)
        {
            this.watchOnlyWalletManager = watchOnlyWalletManager;
            this.logger = loggerFactory.CreateLogger(this.GetType().FullName);
        }

        /// <summary>
        /// Gets the list of addresses being watched along with the transactions affecting them.
        /// </summary>
        /// <example>Request URL: /api/watchonlywallet </example>
        /// <returns>The watch-only wallet or a collection of errors, if any.</returns>
        [Route("list-watched-addresses")]
        [HttpGet]
        public IActionResult GetWatchOnlyWallet()
        {
            try
            {
                // Map a watch-only wallet to a model object for display in the front end.
                var watchOnlyWallet = this.watchOnlyWalletManager.GetWatchOnlyWallet();
                WatchOnlyWalletModel model = new WatchOnlyWalletModel
                {
                    CoinType = watchOnlyWallet.CoinType,
                    Network = watchOnlyWallet.Network,
                    CreationTime = watchOnlyWallet.CreationTime
                };

                foreach (var watchAddress in watchOnlyWallet.WatchedAddresses)
                {
                    WatchedAddressModel watchedAddressModel = new WatchedAddressModel
                    {
                        Address = watchAddress.Value.Address,
                        Transactions = new List<TransactionModel>()
                    };

                    foreach (var transactionData in watchAddress.Value.Transactions)
                    {
                        watchedAddressModel.Transactions.Add(new TransactionBriefModel(transactionData.Value.Transaction, watchOnlyWallet.Network));
                    }

                    model.WatchedAddresses.Add(watchedAddressModel);
                }

                foreach (var transaction in watchOnlyWallet.WatchedTransactions)
                {
                    WatchedTransactionModel watchedTransactionModel = new WatchedTransactionModel
                    {
                        Transaction = new TransactionBriefModel(transaction.Value.Transaction, watchOnlyWallet.Network)
                    };

                    model.WatchedTransactions.Add(watchedTransactionModel);
                }

                return this.Json(model);
            }
            catch (Exception e)
            {
                return ErrorHelpers.BuildErrorResponse(HttpStatusCode.BadRequest, e.Message, e.ToString());
            }
        }

        /// <summary>
        /// Adds a base58 address to the watch list.
        /// </summary>
        /// <example>Request URL: /api/watchonlywallet/watch?address=mpK6g... </example>
        /// <param name="address">The base58 address to add to the watch list.</param>
        [Route("watch")]
        [HttpPost]
        public IActionResult Watch([FromQuery]string address)
        {
            // Checks the request is valid.
            if (string.IsNullOrEmpty(address))
            {
                return ErrorHelpers.BuildErrorResponse(HttpStatusCode.BadRequest, "Formatting error", "Address to watch is missing.");
            }

            try
            {
                this.watchOnlyWalletManager.WatchAddress(address);
                return this.Ok();
            }
            catch (Exception e)
            {
                return ErrorHelpers.BuildErrorResponse(HttpStatusCode.Conflict, e.Message, e.ToString());
            }
        }

        [Route("rescan")]
        [HttpPost]
        public IActionResult Rescan([FromQuery]DateTimeOffset fromTime)
        {
            try
            {
                RescanState rescanState = this.watchOnlyWalletManager.Rescan(fromTime);

                RescanStateModel model = new RescanStateModel()
                {
                    IsInProgress = rescanState.IsInProgress,
                    FromTime = rescanState.FromTime,
                    UntilTime = rescanState.UntilTime,
                    ProgressPercentage = rescanState.ProgressPercentage
                };

                return this.Json(model);
            }
            catch (Exception e)
            {
                return ErrorHelpers.BuildErrorResponse(HttpStatusCode.Conflict, e.Message, e.ToString());
            }
        }

        [Route("watch-and-rescan")]
        [HttpPost]
        public IActionResult WatchAndRescan([FromQuery]string address, [FromQuery]DateTimeOffset fromTime)
        {
            if (Watch(address) == this.Ok())
            {
                return Rescan(fromTime);
            }

            return this.BadRequest();
        }

        [Route("list-transactions")]
        [HttpPost]
        public IActionResult ListTransactions([FromQuery]string address)
        {
            // Checks the request is valid.
            if (string.IsNullOrEmpty(address))
            {
                return ErrorHelpers.BuildErrorResponse(HttpStatusCode.BadRequest, "Formatting error", "Address to watch is missing.");
            }

            try
            {
                var watchOnlyWallet = this.watchOnlyWalletManager.GetWatchOnlyWallet();

                if (!watchOnlyWallet.WatchedAddresses.Any(adr => adr.Value.Address == address))
                {
                    return ErrorHelpers.BuildErrorResponse(HttpStatusCode.BadRequest, "Data error", "Address is not in he watchlist. Please add it first with the 'watch' API and use the 'rescan' API if necessary.");
                }

                var watchedAddress = watchOnlyWallet.WatchedAddresses.First(adr => adr.Value.Address == address).Value;
                WatchedAddressModel watchedAddressModel = new WatchedAddressModel
                {
                    Address = watchedAddress.Address,
                    Transactions = new List<TransactionModel>()
                };

                    foreach (KeyValuePair<string, TransactionData> transactionData in watchAddress.Value.Transactions)
                    {
                        Transaction transaction = watchOnlyWallet.Network.CreateTransaction(transactionData.Value.Hex);
                        watchedAddressModel.Transactions.Add(new TransactionVerboseModel(transaction, watchOnlyWallet.Network));
                    }

                return this.Json(watchedAddressModel);
            }
            catch (Exception e)
            {
                return ErrorHelpers.BuildErrorResponse(HttpStatusCode.Conflict, e.Message, e.ToString());
            }
        }

                foreach (KeyValuePair<string, TransactionData> transaction in watchOnlyWallet.WatchedTransactions)
                {
                    var watchedTransactionModel = new WatchedTransactionModel
                    {
                        Transaction = new TransactionVerboseModel(watchOnlyWallet.Network.CreateTransaction(transaction.Value.Hex), watchOnlyWallet.Network)
                    };

            try
            {
                var watchOnlyWallet = this.watchOnlyWalletManager.GetWatchOnlyWallet();

                if (!watchOnlyWallet.WatchedAddresses.Any(adr => adr.Value.Address == request.Address))
                {
                    return ErrorHelpers.BuildErrorResponse(HttpStatusCode.BadRequest, "Data error", "Address is not in he watchlist. Please add it first with the 'watch' API and use the 'rescan' API if necessary.");
                }

                var watchedAddress = watchOnlyWallet.WatchedAddresses.First(adr => adr.Value.Address == request.Address).Value;

                List<SpendableTransactionOutModel> transactionOutList = new List<SpendableTransactionOutModel>();
                foreach (TransactionData watchedTransaction in watchedAddress.Transactions.Values)
                {
                    Transaction tr = watchedTransaction.Transaction;

                    foreach (var txOut in tr.Outputs.AsIndexedOutputs())
                    {
                        if (txOut.TxOut.Value == 0) continue;

                        BitcoinAddress txOutAddress = txOut.TxOut.ScriptPubKey.GetDestinationAddress(watchOnlyWallet.Network);

                        if ((txOutAddress == null) || (txOutAddress.ToString() != watchedAddress.Address)) continue;

                        transactionOutList.Add(new SpendableTransactionOutModel()
                        {
                            Address = txOutAddress.ToString(),
                            TransactionHash = tr.GetHash(),
                            Index = txOut.N,
                            Amount = txOut.TxOut.Value,
                            ScriptPubKeyHex = txOut.TxOut.ScriptPubKey.ToHex()
                        });
                    }
                }

                ListSpendableTransactionOutsModel model = new ListSpendableTransactionOutsModel
                {
                    Network = watchOnlyWallet.Network.ToString(),
                    SpendableTransactionOuts = transactionOutList
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
        /// Builds an <see cref="IActionResult"/> containing errors contained in the <see cref="ControllerBase.ModelState"/>.
        /// </summary>
        /// <returns>A result containing the errors.</returns>
        private static IActionResult BuildErrorResponse(ModelStateDictionary modelState)
        {
            List<ModelError> errors = modelState.Values.SelectMany(e => e.Errors).ToList();
            return ErrorHelpers.BuildErrorResponse(
                HttpStatusCode.BadRequest,
                string.Join(Environment.NewLine, errors.Select(m => m.ErrorMessage)),
                string.Join(Environment.NewLine, errors.Select(m => m.Exception?.Message)));
        }
    }
}
