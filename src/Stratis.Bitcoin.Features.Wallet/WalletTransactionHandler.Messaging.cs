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
            // TODO: add the sender's and the recipient's PubKeyHashes to the parameters and implement encryption
            context.TransactionBuilder.SendMessage(null, null, context.Message, false);
        }
    }
}
