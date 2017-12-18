namespace NBitcoin
{
    public partial class TransactionBuilder
    {

        /// <summary>
        /// Impland a message as PushData into a transaction
        /// </summary>
        /// <returns></returns>
        public TransactionBuilder SendMessage(string message, bool encryptMessage, byte[] publicKeyExponent, byte[] publicKeyModulus,
            byte[] privateKeyDP, byte[] privateKeyDQ, byte[] privateKeyExponent, byte[] privateKeyModulus, byte[] privateKeyP, byte[] privateKeyPublicExponent, byte[] privateKeyQ, byte[] privateKeyQInv)
        {
            var output = new TxOut()
            {
                ScriptPubKey = TxMessageTemplate.Instance.GenerateScriptPubKey(message, encryptMessage, publicKeyExponent, publicKeyModulus, privateKeyDP, privateKeyDQ, privateKeyExponent, privateKeyModulus, privateKeyP, privateKeyPublicExponent, privateKeyQ, privateKeyQInv)                
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
