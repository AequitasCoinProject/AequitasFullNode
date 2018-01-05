using System.Collections.Generic;
using NBitcoin;
using Newtonsoft.Json;

namespace Stratis.Bitcoin.Features.Wallet.Models
{
    public class WalletGetMessagesModel
    {
        [JsonProperty(PropertyName = "minimumBlockHeight")]
        public int MinimumBlockHeight;

        [JsonProperty(PropertyName = "messages")]
        public ICollection<TxMessageModel> Messages { get; set; }
    }

    public class TxMessageModel
    {
        [JsonProperty(PropertyName = "isPropagated")]
        public bool IsPropagated { get; set; }

        [JsonProperty(PropertyName = "blockHeight")]
        public int? BlockHeight { get; set; }

        [JsonProperty(PropertyName = "transactionHash")]
        public string TransactionHash { get; set; }

        [JsonProperty(PropertyName = "outputIndex")]
        public int MessageOutputIndex { get; set; }

        [JsonProperty(PropertyName = "transactionHex")]
        public string TransactionHex { get; set; }
    }

    public class PublicReviewerAddressModel
    {
        [JsonProperty(PropertyName = "network")]
        public string Network { get; set; }

        [JsonProperty(PropertyName = "address")]
        public string Address { get; set; }

        [JsonProperty(PropertyName = "groupId")]
        public string GroupId { get; set; }
    }

    public class ListPublicReviewerAddressesModel
    {
        [JsonProperty(PropertyName = "reviewerAddresses")]
        public ICollection<PublicReviewerAddressModel> Addresses { get; set; }
    }
}
