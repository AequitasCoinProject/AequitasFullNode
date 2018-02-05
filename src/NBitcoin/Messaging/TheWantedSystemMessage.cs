using System;
using System.Collections.Generic;
using System.Text;
using Newtonsoft.Json;

namespace NBitcoin.Messaging
{
    public enum MessageCompression { None = 0, GZip = 1 }

    public enum MessageChecksum { None = 0 }

    public enum MessageEncryption { None = 0, RSA4096AES256 = 1 }

    public class SecureMessageMetadata
    {
        [JsonProperty(PropertyName = "creationTime")]
        public string CreationTimeUtc;

        [JsonProperty(PropertyName = "recipientAddress")]
        public string RecipientAddress;

        [JsonProperty(PropertyName = "replyToAddress")]
        public string ReplyToAddress;

        [JsonProperty(PropertyName = "rewardAddress")]
        public string RewardAddress;

        public override string ToString()
        {
            return JsonConvert.SerializeObject(this);
        }
    }

    public class SecureMessage
    {
        public byte Version { get; set; } = 1;

        public MessageCompression Compression { get; set; } = MessageCompression.GZip;

        public MessageChecksum ChecksumType { get; set; } = MessageChecksum.None;

        public MessageEncryption Encryption { get; set; }

        public SecureMessageMetadata Metadata;

        public string Text;
    }
}
