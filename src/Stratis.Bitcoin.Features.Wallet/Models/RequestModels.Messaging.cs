using System;
using System.ComponentModel.DataAnnotations;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Stratis.Bitcoin.Features.Wallet.Validations;

namespace Stratis.Bitcoin.Features.Wallet.Models
{
    public class DeserializeTransactionRequest : RequestModel
    {
        [Required(ErrorMessage = "A transaction in hexadecimal format is required.")]
        public string Hex { get; set; }
    }

    /// <summary>
    /// Model object for <see cref="WalletController.GetTipFeeEstimate"/> request.
    /// </summary>
    /// <seealso cref="Stratis.Bitcoin.Features.Wallet.Models.RequestModel" />
    public class EstimateWantedSystemMessageFeeRequest : RequestModel
    {
        [JsonProperty(Order = 1)]
        [Required(ErrorMessage = "The name of the wallet is missing.")]
        public string WalletName { get; set; }

        [JsonProperty(Order = 3)]
        [Required(ErrorMessage = "The name of the account is missing.")]
        public string AccountName { get; set; }

        [JsonProperty(Order = 4)]
        [Required(ErrorMessage = "A payer address is required.")]
        [IsBitcoinAddress()]
        public string PayerAddress { get; set; }

        [JsonProperty(Order = 5)]
        [Required(ErrorMessage = "A destination address is required.")]
        [IsBitcoinAddress()]
        public string DestinationAddress { get; set; }

        [JsonProperty(Order = 6)]
        [Required(ErrorMessage = "The text message of the tip.")]
        public string Message { get; set; }

        [JsonProperty(Order = 7)]
        public bool EncryptMessage { get; set; }
    }

    public class BuildWantedSystemMessageRequest : EstimateWantedSystemMessageFeeRequest
    {
        [JsonProperty(Order = 2)]
        public string WalletPassword { get; set; }
    }

    public class SendWantedSystemMessageRequest : RequestModel
    {
        [Required(ErrorMessage = "A transaction in hexadecimal format is required.")]
        public string Hex { get; set; }
    }

    public class GetWantedSystemMessagesRequest : RequestModel
    {
        public string BlockHeight { get; set; }
    }

    public class DecryptWantedSystemMessageRequest : RequestModel
    {
        public string TransactionHex { get; set; }

        public int MessageOutputIndex { get; set; }

        public string RsaPrivateKeyHex { get; set; }
    }

    public class CreateReviewerAddressRequest : RequestModel
    {
        public string RsaPassword { get; set; }

        [Required(ErrorMessage = "The hex-formatted public key array of the addresses who will participate in the review group.")]
        public string[] SignaturePubKeys { get; set; }

        [Required(ErrorMessage = "The number of signatures needed to accept a tip.")]
        public int RequeiredSignatureCount { get; set; }

        [Required(ErrorMessage = "The public name of the reviewer group. (e.g. 'The Wanted System - County Office'")]
        public string PublicName { get; set; }

        [Required(ErrorMessage = "The name of the reviewer group. (e.g. 'The Wanted System Reviewer's Group')")]
        public string GroupName { get; set; }

        [Required(ErrorMessage = "The public API URL of the reviewer group. (e.g. 'node.thewantedsystem.com:38221')")]
        public string PublicApiUrl { get; set; }

        [JsonIgnore]
        public DateTimeOffset ValidFrom
        {
            get
            {
                DateTimeOffset result;

                if (!DateTimeOffset.TryParse(this.ValidFromStr, out result))
                {
                    result = DateTimeOffset.MinValue;
                }

                return result;
            }

            set
            {
                this.ValidFromStr = value.ToString("o");
            }
        }

        [JsonIgnore]
        public DateTimeOffset ValidUntil
        {
            get
            {
                DateTimeOffset result;

                if (!DateTimeOffset.TryParse(this.ValidUntilStr, out result))
                {
                    result = DateTimeOffset.MaxValue;
                }

                return result;
            }

            set
            {
                this.ValidUntilStr = value.ToString("o");
            }
        }

    [JsonProperty(PropertyName = "validFrom")]
        [Required(ErrorMessage = "The generated multi-sig address will be valid from this time. (e.g. '2018-03-01 14:43:25 +01:00')")]
        public string ValidFromStr { get; set; }

        [JsonProperty(PropertyName = "validUntil")]
        [Required(ErrorMessage = "The generated multi-sig address will be valid until this time. (e.g. '2018-03-08 08:00:00 +00:00')")]
        public string ValidUntilStr { get; set; }

    }

    public class ListReviewerAddressesRequest : RequestModel
    {
        public string GroupId { get; set; }

        public string PublicNameFragment { get; set; }

        public DateTimeOffset? ValidAt { get; set; }
    }

    public class SignWantedSystemMessageRequest : RequestModel
    {
        [JsonProperty(PropertyName = "transactionHex")]
        public string TransactionHex { set; get; }

        [JsonProperty(PropertyName = "signingKey")]
        public string SigningKey { set; get; }
    }

    public class UploadWantedSystemMessageRequest : RequestModel
    {
        [JsonProperty(PropertyName = "transactionHex")]
        public string TransactionHex { set; get; }
    }

    public class ListAccountAddressesWithKeysRequest : RequestModel
    {
        [Required]
        public string WalletName { get; set; }

        [Required]
        public string WalletPassword { get; set; }

        [Required]
        public string AccountName { get; set; }
    }

    public class ListSpendableTransactionOutsRequest : RequestModel
    {
        public string Address { get; set; }

        public string WalletName { get; set; }

        public string AccountName { get; set; }

        [Required]
        public int MinConfirmations { get; set; }
    }

}