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
            this.InitializeTransactionBuilder(context);

            //context.TransactionBuilder = new TransactionBuilder();
            //context.TransactionBuilder.Send(recipient.ScriptPubKey, recipient.Amount);

            // TODO: set (the payer's) input coins
            // this.AddCoins(context);

            //var coins = new List<Coin>();
            //foreach (var item in context.UnspentOutputs.OrderByDescending(a => a.Transaction.Amount))
            //{
            //    coins.Add(new Coin(item.Transaction.Id, (uint)item.Transaction.Index, item.Transaction.Amount, item.Transaction.ScriptPubKey));
            //    sum += item.Transaction.Amount;
            //}

            //context.TransactionBuilder.AddCoins(coins);

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
    }
}
