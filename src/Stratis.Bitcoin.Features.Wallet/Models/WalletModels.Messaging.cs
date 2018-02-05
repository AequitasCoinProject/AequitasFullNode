using System;
using System.Collections.Generic;
using NBitcoin;
using Newtonsoft.Json;

namespace Stratis.Bitcoin.Features.Wallet.Models
{
    public class GetWantedSystemMessagesModel
    {
        [JsonProperty(PropertyName = "minimumBlockHeight")]
        public int MinimumBlockHeight;

        [JsonProperty(PropertyName = "messages")]
        public ICollection<WantedSystemMessageModel> Messages { get; set; }
    }
    
    public class WantedSystemMessageModel
    {
        [JsonProperty(PropertyName = "isPropagated")]
        public bool IsPropagated { set; get; }

        [JsonProperty(PropertyName = "blockHeight")]
        public int? BlockHeight { set; get; }

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

        [JsonProperty(PropertyName = "messageOutputIndex")]
        public int MessageOutputIndex { set; get; }

        [JsonProperty(PropertyName = "transactionHex")]
        public string TransactionHex { set; get; }
    }

    public class DecryptedWantedSystemMessageModel
    {
        [JsonProperty(PropertyName = "version")]
        public byte Version { get; set; }

        [JsonProperty(PropertyName = "compression")]
        public string Compression { get; set; }

        [JsonProperty(PropertyName = "checksumType")]
        public string ChecksumType { get; set; }

        [JsonProperty(PropertyName = "encryption")]
        public string Encryption { get; set; }

        [JsonProperty(PropertyName = "metadata")]
        public string Metadata { set; get; }

        [JsonProperty(PropertyName = "text")]
        public string Text { set; get; }
    }

    public class PublicReviewerAddressModel
    {
        [JsonProperty(PropertyName = "network")]
        public string Network { get; set; }

        [JsonProperty(PropertyName = "address")]
        public string Address { get; set; }

        [JsonProperty(PropertyName = "publicName")]
        public string PublicName { get; set; }

        [JsonProperty(PropertyName = "groupId")]
        public string GroupId { get; set; }

        [JsonProperty(PropertyName = "groupName")]
        public string GroupName { get; set; }

        [JsonProperty(PropertyName = "validFrom")]
        public int ValidFrom { get; set; }

        [JsonProperty(PropertyName = "validUntil")]
        public int ValidUntil { get; set; }

        [JsonProperty(PropertyName = "encryptionPublicKey")]
        public string RsaPublicKeyHex { get; set; }        

        [JsonProperty(PropertyName = "encryptionPrivateKey")]
        public string RsaPrivateKeyHex { get; set; }

        [JsonProperty(PropertyName = "managerPasswordHash")]
        public string RsaPasswordHashHex { get; set; }
    }

    public class ListPublicReviewerAddressesModel
    {
        [JsonProperty(PropertyName = "reviewerAddresses")]
        public ICollection<PublicReviewerAddressModel> Addresses { get; set; }
    }
}
