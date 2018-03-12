using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Text;

namespace Stratis.Bitcoin.Features.WatchOnlyWallet.Models
{
    public class ListWatchedSpendableTransactionsRequest : RequestModel
    {
        public string Address { get; set; }
    }

}
