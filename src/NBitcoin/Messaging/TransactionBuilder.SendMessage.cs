using NBitcoin.Crypto;

namespace NBitcoin
{
    public partial class TransactionBuilder
    {
        /// <summary>
        /// Impland a message as PushData into a transaction
        /// </summary>
        /// <returns></returns>
        public TransactionBuilder SendMessage(string message, string messageRecipient, string replyToAddress, string rewardAddress, RsaPublicKey publicKey = null, RsaPrivateKey privateKey = null)
        {
            var output = new TxOut()
            {
                ScriptPubKey = WantedSystemMessageTemplate.Instance.GenerateScriptPubKey(message, messageRecipient, replyToAddress, rewardAddress, (publicKey != null), publicKey, privateKey)
            };
            // change the txout's value dynamically to the smallest amount (the dust threshold)
            output.Value = output.GetDustThreshold(this.StandardTransactionPolicy.MinRelayTxFee);

            var builder = new SendMessageBuilder(output);

            this.CurrentGroup.Builders.Add(builder.Build);
            return this;
        }

        class SendMessageBuilder
        {
            internal TxOut _TxOut;

            public SendMessageBuilder(TxOut txout)
            {
                _TxOut = txout;
            }

            public Money Build(TransactionBuildingContext ctx)
            {
                ctx.Transaction.Outputs.Add(_TxOut);
                return _TxOut.Value;
            }
        }        
    }
}
