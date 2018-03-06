#if !NOJSONNET
using System;
using System.Reflection;
using Newtonsoft.Json;

namespace NBitcoin.JsonConverters
{
#if !NOJSONNET
    public
#else
    internal
#endif
    class DateTimeToUnixTimeConverter : JsonConverter
    {
        public override bool CanConvert(Type objectType)
        {
            return typeof(DateTime).GetTypeInfo().IsAssignableFrom(objectType.GetTypeInfo()) ||
                typeof(DateTimeOffset).GetTypeInfo().IsAssignableFrom(objectType.GetTypeInfo()) ||
                typeof(DateTimeOffset?).GetTypeInfo().IsAssignableFrom(objectType.GetTypeInfo());
        }

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            Nullable<DateTimeOffset> result = null;

            if (reader.Value != null)
            {
                if (reader.Value is Nullable<DateTimeOffset>)
                {
                    result = reader.Value as Nullable<DateTimeOffset>;
                }
                else if (reader.Value is Nullable<DateTime>)
                {
                    result = reader.Value as Nullable<DateTime>;
                }
                else if (reader.Value is string)
                {
                    if (!String.IsNullOrWhiteSpace(reader.Value as string))
                    {
                        DateTimeOffset dto;
                        if (DateTimeOffset.TryParse(reader.Value as string, out dto))
                        {
                            result = dto;
                        }
                    }
                }
                else
                {
                    result = Utils.UnixTimeToDateTime((ulong)(long)reader.Value);
                }
            }

            if (objectType == typeof(DateTime)) return result.Value.UtcDateTime;
            if (objectType == typeof(DateTimeOffset)) return result.Value;
            return result;
        }

        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            DateTime time;
            if (value is DateTime)
                time = (DateTime)value;
            else
                time = ((DateTimeOffset)value).UtcDateTime;

            if (time < Utils.UnixTimeToDateTime(0))
                time = Utils.UnixTimeToDateTime(0).UtcDateTime;
            writer.WriteValue(Utils.DateTimeToUnixTime(time));
        }
    }
}
#endif