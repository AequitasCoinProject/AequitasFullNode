using System;
using System.Collections.Generic;
using System.Text;
using Newtonsoft.Json;

namespace Stratis.Bitcoin.Features.WatchOnlyWallet.Models
{
    public class RescanStateModel
    {
        [JsonProperty(PropertyName = "isInProgress")]
        public bool IsInProgress { get; set; }

        [JsonProperty(PropertyName = "fromTime")]
        public DateTimeOffset FromTime { get; set; }

        [JsonProperty(PropertyName = "untilTime")]
        public DateTimeOffset UntilTime { get; set; }

        [JsonProperty(PropertyName = "progressPercentage")]
        public double ProgressPercentage { get; set; }
    }
}
