using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace NBitcoin
{
    public class MoneyUnit
    {
        public string Name { get; private set; }
        public int Multiplier { get; private set; }

        public MoneyUnit(string name, int multiplier)
        {
            this.Name = name;
            this.Multiplier = multiplier;
        }

        public MoneyUnit(int multiplier)
        {
            this.Name = "";
            this.Multiplier = multiplier;
        }

        public static MoneyUnit AtomicUnit
        {
            get
            {
                return new MoneyUnit(1);
            }
        }
    }

    public class MoneyUnits
    {
        public MoneyUnit[] Units
        {
            get;
            private set;
        }

        public MoneyUnit DefaultUnit
        {
            get;
            private set;
        }

        public MoneyUnit AtomicUnit
        {
            get;
            private set;
        }

        public MoneyUnits(string defaultUnit, MoneyUnit[] units)
        {
            this.Units = units;
            this.DefaultUnit = this.Units.First(mu => mu.Name.ToLowerInvariant() == defaultUnit.ToLowerInvariant());
            this.AtomicUnit = this.Units.FirstOrDefault(mu => mu.Multiplier == 1);
            if (this.AtomicUnit == null) this.AtomicUnit = MoneyUnit.AtomicUnit;
        }

        public MoneyUnit GetMoneyUnit(string moneyUnitName)
        {
            return this.Units.FirstOrDefault(mu => mu.Name.ToLowerInvariant() == moneyUnitName.ToLowerInvariant());
        }

        public string ToString(int units)
        {
            return ((decimal)units / this.DefaultUnit.Multiplier) + " " + this.DefaultUnit.Name;
        }
    }
}
