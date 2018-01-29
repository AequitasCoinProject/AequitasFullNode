using System;
using System.ComponentModel.DataAnnotations;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Stratis.Bitcoin.Features.Wallet.Validations;

namespace Stratis.Bitcoin.Features.Wallet.Models
{
    /// <summary>
    /// Model object for <see cref="WalletController.GetTipFeeEstimate"/> request.
    /// </summary>
    /// <seealso cref="Stratis.Bitcoin.Features.Wallet.Models.RequestModel" />
    public class TipFeeEstimateRequest : RequestModel
    {
        [Required(ErrorMessage = "The name of the wallet is missing.")]
        public string WalletName { get; set; }

        [Required(ErrorMessage = "The name of the account is missing.")]
        public string AccountName { get; set; }

        [Required(ErrorMessage = "A destination address is required.")]
        [IsBitcoinAddress()]
        public string DestinationAddress { get; set; }

        [Required(ErrorMessage = "The text message of the tip.")]
        public string Message { get; set; }

        public bool EncryptMessage { get; set; }
    }

    public class BuildTipTransactionRequest : TipFeeEstimateRequest
    {
        [Required(ErrorMessage = "A password is required.")]
        public string Password { get; set; }
    }

    public class SendTipTransactionRequest : RequestModel
    {
        [Required(ErrorMessage = "A transaction in hexadecimal format is required.")]
        public string Hex { get; set; }
    }

    public class GetTipMessagesRequest : RequestModel
    {
        [Required(ErrorMessage = "The block height from which you need the messages must be defined.")]
        public string BlockHeight { get; set; }
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

        [Required(ErrorMessage = "The generated multi-sig address will be valid from this block index.")]
        public int? ValidFrom { get; set; }

        [Required(ErrorMessage = "The generated multi-sig address will be valid until this block index.")]
        public int? ValidUntil { get; set; }
    }

    public class ListReviewerAddressesRequest : RequestModel
    {
        public string GroupId { get; set; }

        public string PublicNameFragment { get; set; }

        public int ValidAtBlockHeight { get; set; }
    }
}