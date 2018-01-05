using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using NBitcoin;
using Newtonsoft.Json;
using Stratis.Bitcoin.Broadcasting;
using Stratis.Bitcoin.Configuration;
using Stratis.Bitcoin.Features.Wallet.Interfaces;
using Stratis.Bitcoin.Interfaces;
using Stratis.Bitcoin.Utilities;

[assembly: InternalsVisibleTo("Stratis.Bitcoin.Features.Wallet.Tests")]

namespace Stratis.Bitcoin.Features.Wallet
{
    public class TxMessageTransaction
    {
        [JsonProperty(PropertyName = "isPropagated")]
        public bool IsPropagated { set; get; }

        [JsonProperty(PropertyName = "blockHeight")]
        public int? BlockHeight { set; get; }

        [JsonIgnore]
        public uint256 TransactionHash { set; get; }

        [JsonProperty(PropertyName = "transactionHash")]
        public string TransactionHashHex { set; get; }

        [JsonProperty(PropertyName = "outputIndex")]
        public int OutputIndex { set; get; }

        [JsonProperty(PropertyName = "transactionHex")]
        public string TransactionHex { set; get; }
    }

    /// <summary>
    /// A manager providing operations on wallets.
    /// </summary>
    public partial class WalletManager : IWalletManager
    {
        /// <summary>The file name of the messages file.</summary>
        internal const string MessagesFileName = "messages.json";

        private Dictionary<uint256, TxMessageTransaction> txMessages;

        public Dictionary<uint256, TxMessageTransaction> TxMessages
        {
            get
            {
                if (this.txMessages == null)
                {
                    this.txMessages = new Dictionary<uint256, TxMessageTransaction>();
                    LoadMessages();
                }

                return this.txMessages;
            }
        }

        private void AddMessageTransactionToMessageStore(string transactionHex, uint256 transactionHash, int utxoIndex, Script script,
            int? blockHeight, Block block, bool isPropagated)
        {
            this.logger.LogTrace("({0}:'{1}',{2}:'{3}',{4}:{5},{6}:{7})", nameof(transactionHex), transactionHex,
                nameof(transactionHash), transactionHash, nameof(utxoIndex), utxoIndex, nameof(blockHeight), blockHeight);

            if (!this.TxMessages.ContainsKey(transactionHash))
            {
                this.logger.LogTrace("Message '{0}-{1}' was not found in the message store, adding it.", transactionHash, utxoIndex);

                this.TxMessages.Add(transactionHash, new TxMessageTransaction()
                {
                    TransactionHex = transactionHex,
                    TransactionHash = transactionHash,
                    TransactionHashHex = transactionHash.ToString(),
                    OutputIndex = utxoIndex,
                    BlockHeight = blockHeight,
                    IsPropagated = isPropagated
                });

                SaveMessages();
            } else
            {
                this.logger.LogTrace("Message '{0}-{1}' was already in the message store, skipping it.", transactionHash, utxoIndex);
            }

            this.logger.LogTrace("(-)");
        }

        /// <inheritdoc />
        public void LoadMessages()
        {
            var messageFileStorage = new FileStorage<List<TxMessageTransaction>>(this.fileStorage.FolderPath);
            try
            {
                var messages = messageFileStorage.LoadByFileName(MessagesFileName);
                messages.ForEach(message =>
                {
                    //byte[] hashBytes = Convert.FromBase64String(message.TransactionHashBase64);
                    message.TransactionHash = new uint256(message.TransactionHashHex);
                    this.txMessages.TryAdd(message.TransactionHash, message);
                });
            }
            catch (System.IO.FileNotFoundException)
            {
                // we don't have a messages file yet, but that's alright
            }
        }

        /// <inheritdoc />
        public void SaveMessages()
        {
            if (this.txMessages.Any() == false)
                return;

            var fileStorage = new FileStorage<List<TxMessageTransaction>>(this.fileStorage.FolderPath);
            fileStorage.SaveToFile(this.txMessages.OrderBy(m => m.Value.BlockHeight).Select(m => m.Value).ToList(), MessagesFileName);
        }

    }
}
