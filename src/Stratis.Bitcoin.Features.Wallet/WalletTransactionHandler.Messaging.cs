using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Extensions.Logging;
using NBitcoin;
using NBitcoin.Policy;
using Stratis.Bitcoin.Features.Wallet.Interfaces;
using Stratis.Bitcoin.Utilities;

namespace Stratis.Bitcoin.Features.Wallet
{
    public partial class WalletTransactionHandler : IWalletTransactionHandler
    {
        private void AddMessage(TransactionBuildContext context)
        {
            // add the sender's and the recipient's PubKeyHashes to the parameters and implement encryption
            HdAddress hdAddress = this.walletManager.GetUnusedAddress(context.AccountReference);

            Wallet wallet = this.walletManager.GetWallet(context.AccountReference.WalletName);
            ISecret privateKey = wallet.GetExtendedPrivateKeyForAddress(context.WalletPassword, hdAddress);

            PubKey publicKey = privateKey.PrivateKey.PubKey.Decompress();
            string uncompressedPublicKey = publicKey.ToString().Substring(2);

            string compressedPrivateKey = privateKey.PrivateKey.ToString();

            context.TransactionBuilder.SendMessage(uncompressedPublicKey, context.Message, context.EncryptMessage);
        }
    }
}
