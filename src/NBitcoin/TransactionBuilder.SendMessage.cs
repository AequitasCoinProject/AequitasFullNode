using NBitcoin.BuilderExtensions;
using NBitcoin.Crypto;
using NBitcoin.DataEncoders;
using NBitcoin.OpenAsset;
using NBitcoin.Policy;
using NBitcoin.Stealth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.ExceptionServices;
using System.Text;
using System.Threading.Tasks;
using Builder = System.Func<NBitcoin.TransactionBuilder.TransactionBuildingContext, NBitcoin.IMoney>;

namespace NBitcoin
{
    public partial class TransactionBuilder
    {

        /// <summary>
        /// Impland a message as PushData into a transaction
        /// </summary>
        /// <param name="scriptPubKey">The destination</param>
        /// <param name="amount">The amount</param>
        /// <returns></returns>
        public TransactionBuilder SendMessage(ISecret from, IDestination to, string message, bool encryptMessage)
        {            
            var builder = new SendMessageBuilder(new TxOut() { ScriptPubKey = TxMessageTemplate.Instance.GenerateScriptPubKey(message), Value = new Money(4950, MoneyUnit.Satoshi) });
            CurrentGroup.Builders.Add(builder.Build);
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
