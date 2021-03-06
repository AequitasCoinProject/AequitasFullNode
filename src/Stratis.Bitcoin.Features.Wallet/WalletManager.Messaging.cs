﻿using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using NBitcoin;
using Newtonsoft.Json;
using Stratis.Bitcoin.Configuration;
using Stratis.Bitcoin.Features.Wallet.Interfaces;
using Stratis.Bitcoin.Features.Wallet.Models;
using Stratis.Bitcoin.Interfaces;
using Stratis.Bitcoin.Utilities;

[assembly: InternalsVisibleTo("Stratis.Bitcoin.Features.Wallet.Tests")]

namespace Stratis.Bitcoin.Features.Wallet
{    
    /// <summary>
    /// A manager providing operations on wallets.
    /// </summary>
    public partial class WalletManager : IWalletManager
    {
        /// <summary>The file name of the messages file.</summary>
        internal const string MessagesFileName = "messages.json";

        private Dictionary<uint256, WantedSystemMessageModel> wantedSystemMessages;

        public Dictionary<uint256, WantedSystemMessageModel> WantedSystemMessages
        {
            get
            {
                if (this.wantedSystemMessages == null)
                {
                    this.wantedSystemMessages = new Dictionary<uint256, WantedSystemMessageModel>();
                    LoadWantedSystemMessages();
                }

                return this.wantedSystemMessages;
            }
        }

        public WantedSystemMessageModel AddWantedSystemMessageToMessageStore(Transaction transaction)
        {
            var wantedMessageOuts = transaction.Outputs.AsIndexedOutputs().Where(txOut => WantedSystemMessageTemplate.Instance.CheckScriptPubKey(txOut.TxOut.ScriptPubKey));

            if (wantedMessageOuts.Count() == 0)
            {
                throw new Exception("The transaction you provided doesn't contain any Wanted System Messages.");
            }
           
            Transaction txClone = this.network.CreateTransaction(transaction.ToBytes());
            txClone.Inputs.ForEach(txIn => txIn.ScriptSig = null);
            uint256 transactionHash = txClone.GetHash();

            return this.AddWantedSystemMessageToMessageStore(transaction.ToHex(), transactionHash, (int)wantedMessageOuts.First().N, null, null, null, false);
        }

        private WantedSystemMessageModel AddWantedSystemMessageToMessageStore(string transactionHex, uint256 transactionHash, int utxoIndex, Script script,
            int? blockHeight, Block block, bool isPropagated)
        {
            this.logger.LogTrace("({0}:'{1}',{2}:'{3}',{4}:{5},{6}:{7})", nameof(transactionHex), transactionHex,
                nameof(transactionHash), transactionHash, nameof(utxoIndex), utxoIndex, nameof(blockHeight), blockHeight);

            if (!this.WantedSystemMessages.ContainsKey(transactionHash))
            {
                this.logger.LogTrace("Message '{0}-{1}' was not found in the message store, adding it.", transactionHash, utxoIndex);

                this.WantedSystemMessages.Add(transactionHash, new WantedSystemMessageModel()
                {
                    TransactionHex = transactionHex,
                    TransactionHash = transactionHash,
                    TransactionHashHex = transactionHash.ToString(),
                    MessageOutputIndex = utxoIndex,
                    BlockHeight = blockHeight,
                    IsPropagated = isPropagated
                });

                SaveWantedSystemMessages();
            }
            else if ((!this.WantedSystemMessages[transactionHash].BlockHeight.HasValue) && (blockHeight.HasValue))
            {
                this.WantedSystemMessages[transactionHash].BlockHeight = blockHeight;
                this.WantedSystemMessages[transactionHash].IsPropagated = isPropagated;

                SaveWantedSystemMessages();
            }
            else
            {
                this.logger.LogTrace("Message '{0}-{1}' was already in the message store, skipping it.", transactionHash, utxoIndex);
            }

            this.logger.LogTrace("(-)");

            return this.WantedSystemMessages[transactionHash];
        }

        public WantedSystemMessageModel AddPartiallySignedTxToMessageStore(Transaction transaction)
        {
            Transaction txClone = this.network.CreateTransaction(transaction.ToBytes());
            txClone.Inputs.ForEach(txIn => txIn.ScriptSig = null);
            uint256 transactionHash = txClone.GetHash();

            string partiallySignedTransactionHex = transaction.ToHex();

            if (!this.WantedSystemMessages.ContainsKey(transactionHash))
            {
                throw new Exception($"The transcation with hash '{transactionHash}' is not in the message store.");
            }

            if (this.WantedSystemMessages[transactionHash].PartiallySignedTransactions == null)
            {
                this.WantedSystemMessages[transactionHash].PartiallySignedTransactions = new List<PartiallySignedWantedSystemMessagesModel>();
            }

            if (!this.WantedSystemMessages[transactionHash].PartiallySignedTransactions.Any(pswsmm => pswsmm.TransactionHex == partiallySignedTransactionHex))
            {
                //if (this.WantedSystemMessages[transactionHash].TransactionHex != partiallySignedTransactionHex)
                {
                    this.WantedSystemMessages[transactionHash].PartiallySignedTransactions.Add(
                        new PartiallySignedWantedSystemMessagesModel()
                        {
                            TransactionHex = partiallySignedTransactionHex
                        }
                    );
                }
            }

            this.SaveWantedSystemMessages();

            return this.WantedSystemMessages[transactionHash];
        }

        /// <inheritdoc />
        public void LoadWantedSystemMessages()
        {
            var messageFileStorage = new FileStorage<List<WantedSystemMessageModel>>(this.fileStorage.FolderPath);
            try
            {
                var messages = messageFileStorage.LoadByFileName(MessagesFileName);
                messages.ForEach(message =>
                {
                    //byte[] hashBytes = Convert.FromBase64String(message.TransactionHashBase64);
                    message.TransactionHash = new uint256(message.TransactionHashHex);
                    this.wantedSystemMessages.TryAdd(message.TransactionHash, message);
                });
            }
            catch (System.IO.FileNotFoundException)
            {
                // we don't have a messages file yet, but that's alright
            }
        }

        /// <inheritdoc />
        public void SaveWantedSystemMessages()
        {
            if (this.wantedSystemMessages.Any() == false)
                return;

            var fileStorage = new FileStorage<List<WantedSystemMessageModel>>(this.fileStorage.FolderPath);
            fileStorage.SaveToFile(this.wantedSystemMessages.OrderBy(m => m.Value.BlockHeight).Select(m => m.Value).ToList(), MessagesFileName);
        }


        /// <summary>The file name of the reviwer addresses file.</summary>
        internal const string ReviewerAddressesFileName = "reviewers.json";

        private FileSystemWatcher reviewersFileWatcher;

        private Dictionary<string, PublicReviewerAddressModel> reviewerAddresses;

        public Dictionary<string, PublicReviewerAddressModel> ReviewerAddresses
        {
            get
            {
                if (this.reviewerAddresses == null)
                {
                    this.reviewerAddresses = new Dictionary<string, PublicReviewerAddressModel>();
                    LoadReviewerAddresses();
                }

                return this.reviewerAddresses;
            }
        }

        public void AddReviewerAddressToReviewerStore(PublicReviewerAddressModel pra)
        {
            this.logger.LogTrace("({0}:'{1}',{2}:'{3}',{4}:{5})", nameof(pra.GroupId), pra.GroupId,
                nameof(pra.Address), pra.Address, nameof(pra.Network), pra.Network);

            if (!this.ReviewerAddresses.ContainsKey(pra.Address.ToString()))
            {
                this.logger.LogTrace("Reviewer address '{0}' was not found in the reviewer address store, adding it.", pra.Address);

                if (!String.IsNullOrEmpty(pra.GroupId))
                {
                    var existingGroup = this.ReviewerAddresses.Values.FirstOrDefault(ra => ra.GroupId == pra.GroupId);
                    if (existingGroup != null)
                    {
                        // let's use the same name for the same groupIds for every entry
                        pra.GroupName = existingGroup.GroupName;
                    }
                } else if (!String.IsNullOrWhiteSpace(pra.GroupName))
                {
                    var existingGroup = this.ReviewerAddresses.Values.FirstOrDefault(ra => ra.GroupName == pra.GroupName);
                    if (existingGroup != null)
                    {
                        pra.GroupId = existingGroup.GroupId;
                    }
                    else
                    {
                        // we have to generate an ID for this new group
                        pra.GroupId = new Key().ToHex(this.network);
                    }
                }

                this.ReviewerAddresses.Add(pra.Address, pra);

                SaveReviewerAddresses();
            }
            else
            {
                this.logger.LogTrace("Reviewer address '{0}' was already in the reviewer address store, skipping it.", pra.Address);
            }

            this.logger.LogTrace("(-)");
        }

        /// <inheritdoc />
        public void LoadReviewerAddresses()
        {
            var reviwerAddressFileStorage = new FileStorage<List<PublicReviewerAddressModel>>(this.fileStorage.FolderPath);
            try
            {
                var addresses = reviwerAddressFileStorage.LoadByFileName(ReviewerAddressesFileName);
                this.reviewerAddresses.Clear();
                addresses.ForEach(address =>
                {
                    this.reviewerAddresses.TryAdd(address.Address.ToString(), address);
                });

                if (this.reviewersFileWatcher == null)
                {
                    this.reviewersFileWatcher = new FileSystemWatcher(this.fileStorage.FolderPath, ReviewerAddressesFileName);
                    this.reviewersFileWatcher.NotifyFilter = NotifyFilters.LastWrite;
                    this.reviewersFileWatcher.Changed += ReviewersFileChanged;
                    this.reviewersFileWatcher.EnableRaisingEvents = true;
                }
            }
            catch (System.IO.FileNotFoundException)
            {
                // we don't have a reviewer address file yet, but that's alright
            }
        }

        private void ReviewersFileChanged(object sender, FileSystemEventArgs e)
        {
            LoadReviewerAddresses();
        }

        /// <inheritdoc />
        public void SaveReviewerAddresses()
        {
            if (this.reviewerAddresses.Any() == false)
                return;

            if (this.reviewersFileWatcher != null)
            {
                this.reviewersFileWatcher.EnableRaisingEvents = false;
            }

            var fileStorage = new FileStorage<List<PublicReviewerAddressModel>>(this.fileStorage.FolderPath);
            fileStorage.SaveToFile(this.reviewerAddresses.OrderBy(ra => ra.Value.GroupId).Select(ra => ra.Value).ToList(), ReviewerAddressesFileName);

            if (this.reviewersFileWatcher != null)
            {
                this.reviewersFileWatcher.EnableRaisingEvents = true;
            }
        }
    }
}
