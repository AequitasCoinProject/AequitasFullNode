using System;
using System.Collections.Generic;
using System.Text;
using Newtonsoft.Json;

namespace Stratis.Bitcoin.Features.WatchOnlyWallet
{
    public class RescanState
    {
        public bool IsInProgress { get; set; }

        public DateTimeOffset FromTime { get; set; }

        public DateTimeOffset UntilTime { get; set; }

        public double ProgressPercentage { get; set; }
    }
}
