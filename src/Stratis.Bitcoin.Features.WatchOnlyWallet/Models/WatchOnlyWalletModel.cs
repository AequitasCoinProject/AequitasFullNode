using System;
using System.Collections.Generic;
using NBitcoin;
using NBitcoin.DataEncoders;
using Newtonsoft.Json;
using Stratis.Bitcoin.Features.RPC.Models;
using Stratis.Bitcoin.Features.Wallet;
using Stratis.Bitcoin.Utilities.JsonConverters;

namespace Stratis.Bitcoin.Features.WatchOnlyWallet.Models
{
    /// <summary>
    /// Represents a watch-only wallet to be used as an API return object.
    /// </summary>
    public class WatchOnlyWalletModel
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="WatchOnlyWalletModel"/> class.
        /// </summary>
        public WatchOnlyWalletModel()
        {
            this.WatchedAddresses = new List<WatchedAddressModel>();
        }

        /// <summary>
        /// The network this wallet is for.
        /// </summary>
        [JsonProperty(PropertyName = "network")]
        [JsonConverter(typeof(NetworkConverter))]
        public Network Network { get; set; }

        /// <summary>
        /// The type of coin, Bitcoin or Stratis.
        /// </summary>
        [JsonProperty(PropertyName = "coinType")]
        public CoinType CoinType { get; set; }

        /// <summary>
        /// The time this wallet was created.
        /// </summary>
        [JsonProperty(PropertyName = "creationTime")]
        [JsonConverter(typeof(DateTimeOffsetConverter))]
        public DateTimeOffset CreationTime { get; set; }

        /// <summary>
        /// The list of <see cref="WatchedAddress"/>es being watched.
        /// </summary>
        [JsonProperty(PropertyName = "watchedAddresses")]
        public ICollection<WatchedAddressModel> WatchedAddresses { get; set; }

        /// <summary>
        /// The list of transactions being watched.
        /// </summary>
        [JsonProperty(PropertyName = "watchedTransactions")]
        public ICollection<WatchedTransactionModel> WatchedTransactions { get; set; }
    }

    /// <summary>
    /// An object contaning an address being watched along with any transactions affecting it.
    /// </summary>
    public class WatchedAddressModel
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="WatchedAddressModel"/> class.
        /// </summary>
        public WatchedAddressModel()
        {
            this.Transactions = new List<TransactionModel>();
        }

        /// <summary>
        /// A base58 address being watched for transactions affecting it.
        /// </summary>
        [JsonProperty(PropertyName = "address")]
        public string Address { get; set; }

        /// <summary>
        /// The list of transactions affecting the address being watched.
        /// </summary>
        [JsonProperty(PropertyName = "transactions")]
        public ICollection<TransactionModel> Transactions { get; set; }
    }

    /// <summary>
    /// An object contaning a transaction being watched.
    /// </summary>
    public class WatchedTransactionModel
    {
        /// <summary>
        /// The transaction being watched.
        /// </summary>
        [JsonProperty(PropertyName = "transaction")]
        public TransactionModel Transaction { get; set; }
    }

    public class ListSpendableTransactionOutsModel
    {
        public string Network { set; get; }

        public ICollection<SpendableTransactionOutModel> SpendableTransactionOuts { set; get; }
    }

    public class SpendableTransactionOutModel
    {
        public string Address { set; get; }

        [JsonIgnore]
        public uint256 TransactionHash { set; get; }

        [JsonProperty(PropertyName = "transactionHash")]
        public string TransactionHashHex
        {
            set
            {
                this.TransactionHash = uint256.Parse(value);
            }

            get
            {
                return this.TransactionHash.ToString();
            }
        }

        public uint Index { set; get; }

        public long Amount { set; get; }

        [JsonIgnore]
        public NBitcoin.Script ScriptPubKey
        {
            get
            {
                return new NBitcoin.Script(Encoders.Hex.DecodeData(this.ScriptPubKeyHex));
            }
        }

        [JsonProperty(PropertyName = "scriptPubKey")]
        public string ScriptPubKeyHex { get; set; }

    }

}
