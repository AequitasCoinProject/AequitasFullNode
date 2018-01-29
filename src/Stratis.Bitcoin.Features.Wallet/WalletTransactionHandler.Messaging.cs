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
    }
}
