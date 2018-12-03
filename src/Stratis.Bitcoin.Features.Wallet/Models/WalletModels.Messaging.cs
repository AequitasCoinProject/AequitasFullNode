using System;
using System.Collections.Generic;
using NBitcoin;
using NBitcoin.DataEncoders;
using Newtonsoft.Json;

namespace Stratis.Bitcoin.Features.Wallet.Models
{
    public class ListWantedSystemMessagesModel
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

        [JsonProperty(PropertyName = "partiallySignedTransactions")]
        public ICollection<PartiallySignedWantedSystemMessagesModel> PartiallySignedTransactions { get; set; }
    }

    public class PartiallySignedWantedSystemMessagesModel
    {
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
        public string ValidFrom { get; set; }

        [JsonProperty(PropertyName = "validUntil")]
        public string ValidUntil { get; set; }

        [JsonIgnore]
        public Script ScriptPubKey
        {
            get
            {
                return new Script(Encoders.Hex.DecodeData(this.ScriptPubKeyHex));
            }
        }

        [JsonProperty(PropertyName = "scriptPubKey")]
        public string ScriptPubKeyHex { get; set; }

        [JsonProperty(PropertyName = "encryptionPublicKey")]
        public string RsaPublicKeyHex { get; set; }        

        [JsonProperty(PropertyName = "encryptionPrivateKey")]
        public string RsaPrivateKeyHex { get; set; }

        [JsonProperty(PropertyName = "managerPasswordHash")]
        public string RsaPasswordHashHex { get; set; }

        [JsonIgnore]
        private Uri publicApiUrl;

        [JsonProperty(PropertyName = "publicApiUrl")]
        public string PublicApiUrl
        {
            get
            {
                return this.publicApiUrl.ToString();
            }

            set
            {
                if (!value.Contains(":"))
                {
                    value = value + ":38221";
                }

                if (!value.StartsWith("http"))
                {
                    value = "http://" + value;
                }

                this.publicApiUrl = new Uri(value, UriKind.Absolute);
            }
        }
    }

    public class ListPublicReviewerAddressesModel
    {
        [JsonProperty(PropertyName = "reviewerAddresses")]
        public ICollection<PublicReviewerAddressModel> Addresses { get; set; }
    }

    public class SignWantedSystemMessageModel
    {
        [JsonProperty(PropertyName = "transactionHex")]
        public string TransactionHex { set; get; }

        [JsonProperty(PropertyName = "wasSigned")]
        public bool WasSigned { set; get; }
    }

    public class UploadWantedSystemMessageModel
    {
        [JsonProperty(PropertyName = "wantedSystemMessage")]
        public WantedSystemMessageModel WantedSystemMessage { set; get; }
        
        [JsonProperty(PropertyName = "fullySignedTransactionHex")]
        public string FullySignedTransactionHex { set; get; }
    }

    public class ListAccountAddressesWithKeysModel
    {
        public string Network { set; get; }

        public string WalletName { set; get; }

        public string AccountName { set; get; }

        public ICollection<HdAddressModel> ExternalAddresses { set; get; }

        public ICollection<HdAddressModel> InternalAddresses { set; get; }
    }

    public class HdAddressModel
    {
        public string HdPath { set; get; }

        public string Address { set; get; }

        public string PublicKey { set; get; }

        public string PublicKeyHash { set; get; }

        public string PrivateKeyWif { set; get; }

        public int TransactionCount { set; get; }
    }


    public class ListSpendableTransactionsModel
    {
        public string Network { set; get; }

        public string WalletName { set; get; }

        public string AccountName { set; get; }

        public ICollection<DetailedSpendableTransactionModel> SpendableTransactions { set; get; }
    }

    public class DetailedSpendableTransactionModel
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

        public int Index { set; get; }

        public long Amount { set; get; }

        public string ScriptPubKey { set; get; }
    }

}
