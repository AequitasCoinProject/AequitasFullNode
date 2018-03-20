using System;
using System.Collections.Generic;
using NBitcoin;
using Newtonsoft.Json;
using Stratis.Bitcoin.Features.RPC.Models;
using Stratis.Bitcoin.Features.Wallet;
using Stratis.Bitcoin.Utilities.JsonConverters;

namespace Stratis.Bitcoin.Features.WatchOnlyWallet.Models
{    
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

        public string ScriptPubKey { set; get; }
    }

}
