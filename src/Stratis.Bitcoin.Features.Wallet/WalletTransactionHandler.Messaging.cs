using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Extensions.Logging;
using NBitcoin;
using NBitcoin.Crypto;
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
using Stratis.Bitcoin.Features.Wallet.Models;
using Stratis.Bitcoin.Utilities;
using static HashLib.HashFactory.Crypto;

namespace Stratis.Bitcoin.Features.Wallet
{
    public partial class WalletTransactionHandler : IWalletTransactionHandler
    {
        private void AddMessage(TransactionBuildContext context)
        {
            if (context.Message == null) return;

            // load rsa keys from the address book
            Wallet wallet = this.walletManager.GetWallet(context.AccountReference.WalletName);
            WalletManager wm = (WalletManager)this.walletManager;

            if (context.EncryptMessage)
            {
                if (!wm.ReviewerAddresses.ContainsKey(context.MessageRecipient))
                {
                    throw new Exception($"The recipient '{context.MessageRecipient}' was not found in the address book.");
                }

                var reviewerAddress = wm.ReviewerAddresses[context.MessageRecipient];

                context.TransactionBuilder.SendMessage(context.Message, context.MessageRecipient, context.MessageReplyToAddress, context.MessageRewardAddress, RsaPublicKey.FromHex(reviewerAddress.RsaPublicKeyHex), RsaPrivateKey.FromHex(reviewerAddress.RsaPrivateKeyHex));
            } else
            {
                context.TransactionBuilder.SendMessage(context.Message, context.MessageRecipient, context.MessageReplyToAddress, context.MessageRewardAddress);
            }
        }

        /// <inheritdoc />
        public Transaction BuildWantedSystemMessage(TransactionBuildContext context)
        {
            WalletManager wm = this.walletManager as WalletManager;

            this.InitializeTransactionBuilder(context);

            context.TransactionBuilder = new TransactionBuilder();
            //context.TransactionBuilder.Send(recipient.ScriptPubKey, recipient.Amount);

            // TODO: set (the payer's) input coins
            if (wm.ReviewerAddresses.ContainsKey(context.Payer.ToString()))
            {
                //this.AddCoinsFromReviewersAddress(context);
            }
            else
            {
                //this.AddCoins(context);
            }

            // TODO: replace change addresses
            // context.TransactionBuilder.SetChange(context.ChangeAddress.ScriptPubKey);

            // TODO: add the message to the transaction
            // this.AddMessage(context);

            // TODO: set the fee for the transaction
            //var fee = context.TransactionBuilder.EstimateFees(feeRate);
            //context.TransactionBuilder.SendFees(fee);
            //context.TransactionFee = fee;

            // build transaction
            context.Transaction = context.TransactionBuilder.BuildTransaction(false);

            if (context.Sign)
            {
                context.Transaction = context.TransactionBuilder.SignTransaction(context.Transaction);
            }

            //if (!context.TransactionBuilder.Verify(context.Transaction, out TransactionPolicyError[] errors))
            //{
            //    this.logger.LogError($"Build transaction failed: {string.Join(" - ", errors.Select(s => s.ToString()))}");

            //    throw new WalletException("Could not build a transaction, please make sure you entered the correct data.");
            //}

            return context.Transaction;
        }

        private void AddCoinsFromReviewersAddress(TransactionBuildContext context)
        {
            Money totalToSend = new Money(123456789, MoneyUnit.Satoshi);

            Money sum = 0;
            int index = 0;
            var coins = new List<Coin>();
            foreach (var item in context.UnspentOutputs.OrderByDescending(a => a.Transaction.Amount))
            {
                coins.Add(new Coin(item.Transaction.Id, (uint)item.Transaction.Index, item.Transaction.Amount, item.Transaction.ScriptPubKey));
                sum += item.Transaction.Amount;
                index++;

                // If threshold is reached and the total value is above the target
                // then its safe to stop adding UTXOs to the coin list.
                // The primery goal is to reduce the time it takes to build a trx
                // when the wallet is bloated with UTXOs.
                if (index > SendCountThresholdLimit && sum > totalToSend)
                    break;
            }

            // All the UTXOs are added to the builder without filtering.
            // The builder then has its own coin selection mechanism
            // to select the best UTXO set for the corresponding amount.
            // To add a custom implementation of a coin selection override
            // the builder using builder.SetCoinSelection().

            context.TransactionBuilder.AddCoins(coins);
        }
    }
}
