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
