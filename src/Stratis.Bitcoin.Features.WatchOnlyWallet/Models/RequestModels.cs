using System;
using System.Collections.Generic;
using System.Text;
using Newtonsoft.Json;

namespace Stratis.Bitcoin.Features.WatchOnlyWallet.Models
{
    public class RequestModel
    {
        public override string ToString()
        {
            return JsonConvert.SerializeObject(this, Formatting.Indented);
        }
    }
}
