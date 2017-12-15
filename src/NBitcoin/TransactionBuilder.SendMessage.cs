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
        /// <returns></returns>
        public TransactionBuilder SendMessage(string message, bool encryptMessage, byte[] publicKeyExponent, byte[] publicKeyModulus,
            byte[] privateKeyDP, byte[] privateKeyDQ, byte[] privateKeyExponent, byte[] privateKeyModulus, byte[] privateKeyP, byte[] privateKeyPublicExponent, byte[] privateKeyQ, byte[] privateKeyQInv)
        {            
            var builder = new SendMessageBuilder(
                new TxOut()
                {
                    ScriptPubKey = TxMessageTemplate.Instance.GenerateScriptPubKey(message, encryptMessage, publicKeyExponent, publicKeyModulus, privateKeyDP, privateKeyDQ, privateKeyExponent, privateKeyModulus, privateKeyP, privateKeyPublicExponent, privateKeyQ, privateKeyQInv),
                    Value = new Money(4950, MoneyUnit.Satoshi)
                }
                );

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
