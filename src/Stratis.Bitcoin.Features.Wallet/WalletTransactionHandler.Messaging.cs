using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using Microsoft.Extensions.Logging;
using NBitcoin;
using NBitcoin.Crypto;
using NBitcoin.DataEncoders;
using NBitcoin.Policy;
using Newtonsoft.Json;
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
using Stratis.Bitcoin.Features.WatchOnlyWallet.Models;
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
            //context.TransactionBuilder.Send(context.Recipients[0].ScriptPubKey, context.Recipients[0].Amount);

            // set (the payer's) input coins and change address
            if (wm.ReviewerAddresses.ContainsKey(context.PayerAddress.ToString()))
            {
                var coins = this.GetCoinsForReviewersAddress(wm.ReviewerAddresses[context.PayerAddress.ToString()]);
                context.TransactionBuilder.AddCoins(coins);
                context.TransactionBuilder.SetChange(context.PayerAddress);
                context.Sign = false;
            }
            else
            {
                // we are going to pay for this transaction
                var hdAccounts = wm.Wallets.SelectMany(w => w.GetAccountsByCoinType(this.coinType));
                var internalAddresses = hdAccounts.SelectMany(a => a.InternalAddresses).ToList();
                var externalAddresses = hdAccounts.SelectMany(a => a.ExternalAddresses).ToList();
                var allKnownAddresses = internalAddresses.Union(externalAddresses);

                if (allKnownAddresses.Any(address => address.Address.ToString() == context.PayerAddress.ToString()))
                {
                    // we recognise the address, so let's add our inputs/coins and sign the transaction
                    context.Sign = true;
                    this.AddCoins(context);
                    this.AddSecrets(context);
                    context.TransactionBuilder.SetChange(context.ChangeAddress.ScriptPubKey);
                } else
                {
                    throw new Exception("The payer address was not recognised as an address from an opened wallet and it is not a known Reviewers' Group address.");
                }
            }

            // add the message to the transaction
            this.AddMessage(context);

            // set the fee for the transaction
            this.AddFee(context);

            // build transaction
            context.Transaction = context.TransactionBuilder.BuildTransaction(false);

            if (context.Sign)
            {
                context.Transaction = context.TransactionBuilder.SignTransaction(context.Transaction);

                if (!context.TransactionBuilder.Verify(context.Transaction, out TransactionPolicyError[] errors))
                {
                    this.logger.LogError($"Build transaction failed: {string.Join(" - ", errors.Select(s => s.ToString()))}");

                    throw new WalletException($"Could not build a transaction, please make sure you entered the correct data. (Error: '{errors[0].ToString()}', Transaction hex: '{context.Transaction.ToHex()}')");
                }
            }

            return context.Transaction;
        }

        public Coin[] GetCoinsForReviewersAddress(PublicReviewerAddressModel reviewerAddress)
        {
            var result = new List<Coin>();

            // use PublicApiUrl to get the spendable txouts
            ListSpendableTransactionOutsModel spendableTxOuts;

            Uri apiRequestUri = new Uri(new Uri(reviewerAddress.PublicApiUrl), "/api/WatchOnlyWallet/list-spendable-transaction-outs");
            try
            {
                HttpWebRequest apiRequest = (HttpWebRequest)WebRequest.Create(apiRequestUri);

                ASCIIEncoding encoding = new ASCIIEncoding();
                string postData = "{\"address\": \"" + reviewerAddress.Address + "\"}";
                byte[] data = encoding.GetBytes(postData);

                apiRequest.Method = "POST";
                apiRequest.ContentType = "application/json";
                apiRequest.ContentLength = data.Length;

                using (Stream stream = apiRequest.GetRequestStream())
                {
                    stream.Write(data, 0, data.Length);
                }

                HttpWebResponse apiResponse = (HttpWebResponse)apiRequest.GetResponse();

                string responseString = new StreamReader(apiResponse.GetResponseStream()).ReadToEnd();

                spendableTxOuts = JsonConvert.DeserializeObject<ListSpendableTransactionOutsModel>(responseString);

                if (apiResponse.StatusCode != HttpStatusCode.OK)
                {
                    throw new Exception($"The API request '{apiRequestUri.ToString()}' returned the status code '{apiResponse.StatusCode}'.");
                }
            }
            catch (Exception e)
            {
                throw new Exception($"The API request '{apiRequestUri.ToString()}' returned an error '{e.Message}'.");
            }


            Money sum = 0;
            int index = 0;
            foreach (var item in spendableTxOuts.SpendableTransactionOuts.OrderByDescending(a => a.Amount))
            {
                // we would use this if it was not a multi-sig address
                // result.Add(new Coin(item.TransactionHash, (uint)item.Index, item.Amount, reviewerAddress.ScriptPubKey));

                // but we need to use the ToScriptCoin because of the multi-sig
                result.Add(new Coin(item.TransactionHash, (uint)item.Index, item.Amount, item.ScriptPubKey).ToScriptCoin(reviewerAddress.ScriptPubKey));
                sum += item.Amount;
                index++;

                if (index > SendCountThresholdLimit)
                    break;
            }

            return result.ToArray();
        }
    }
}
