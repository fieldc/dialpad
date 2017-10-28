using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

namespace WpfSearcher
{
    struct PhoneNumber  
    {
        public string Npa;
        public string Nxx;
        public string Last4Match;
        public string StarDialCode;

        public PhoneNumber(string npa, string nxx, string last4Match,string starDialCode)
        {
            this.Npa = npa;
            this.Nxx = nxx;
            this.Last4Match = last4Match;
            this.StarDialCode = starDialCode;
        }

        public bool IsStarMatch(string starDial)
        {
            starDial = (starDial.StartsWith("*") ? "" : "*") + starDial;

            if (starDial.Substring(0,4) == this.StarDialCode && Regex.IsMatch(starDial.Substring(4),this.Last4Match))
            {
                return true;
            }
            return false;
        }
        
        public bool IsNpaNxxMatch(string number)
        {
            if ( number.StartsWith(this.Npa+this.Nxx) && Regex.IsMatch(number.Substring(6), this.Last4Match))
            {
                return true;
            }
            return false;
        }

    }
    class DialRules
    {
        List<PhoneNumber> numbers;

        private DialRules()
        {
            numbers = new List<PhoneNumber>();
            
            //ADC
            numbers.Add(new PhoneNumber("770","406","4[0-9]{3}","*500"));
            //AMN
            numbers.Add(new PhoneNumber("913", "906", "41[0-9]{2}", "*266"));
            numbers.Add(new PhoneNumber("913", "906", "45[0-9]{2}", "*266"));
            //CNJ
            numbers.Add(new PhoneNumber("908", "236", "(3[1-4][0-9]{2}|35[0-6][0-9]|36[0-9]{2}|37[0-3][0-9]|37[6-9][0-9])", "*200"));
            numbers.Add(new PhoneNumber("908", "437", "(5[1-2][0-9]{2}|56[5-9][0-9]|57[0-9]{2})", "*200"));
            numbers.Add(new PhoneNumber("908", "849", "(3[8-9][0-9]{2}|7[0-6][0-9]{2}|77[0-5][0-9])", "*200"));
            //HO
            numbers.Add(new PhoneNumber("212", "576", "(26[0-7][0-9]|34[0-9]{2}|37[4-7][0-9]|3[8-9][0-9]{2}|42[4-9][0-9]|4[4-9][0-9]{2}|[5-7][0-9]{2}|8[0-3][0-9]{2}|86[0-9]{2}|89[0-9]{2})", "*100"));
            //OGA
            numbers.Add(new PhoneNumber("202", "654", "(29[4-7][0-9])", "*661"));
            //PNJ
            numbers.Add(new PhoneNumber("973", "394", "([3-4][0-9]{2})", "*400"));
            numbers.Add(new PhoneNumber("973", "952", "(69[0-9]{2})", "*400"));
            numbers.Add(new PhoneNumber("973", "560", "(6[0-2][0-9]{2})", "*400"));
            numbers.Add(new PhoneNumber("973", "515", "(71[2-4][0-9])", "*400"));
            numbers.Add(new PhoneNumber("973", "581", "(73[3-9][0-9])", "*400"));
            numbers.Add(new PhoneNumber("973", "599", "(24[0-9]{2})", "*400"));
            //WHO
            numbers.Add(new PhoneNumber("914", "846", "(3[0-9]{3}|40[0-8][0-9]|409[0-8]|55[0-9]{2}|5[6-9][0-9]{2}|[6-7][0-9]{3})", "*300"));
            //Nautalus
            numbers.Add(new PhoneNumber("972", "720", "(66[0-9]{2}|671[0-9])", "*348"));
            //ZNE
            numbers.Add(new PhoneNumber("914", "847", "(909[3-9]|91[0-9]{2}|92[0-8][0-9]|929[0-2])", "*957"));
            //RENO
            //numbers.Add(new PhoneNumber("914", "847", "(909[3-9]|91[0-9]{2}|92[0-8][0-9]|929[0-2])", "*755"));

           
        }

        public PhoneNumber? GetFromStar(string number)
        {
            foreach (PhoneNumber phone in this.numbers)
            {
                if (phone.IsStarMatch(number))
                    return phone;
            }
            return null;
        }

        public PhoneNumber? GetFromNpaNxx(string number)
        {
            foreach (PhoneNumber phone in this.numbers)
            {
                if (phone.IsNpaNxxMatch(number))
                    return phone;
            }
            return null;
        }

        #region Singleton Creator
        /// <summary>
        /// We need to do it this way for thread safety, this garuntees only on instance
        /// </summary>
        public static DialRules Instance
        {
            get { return Creator.CreatetorInstance; }

        }

        private sealed class Creator
        {
            private static readonly DialRules instance = new DialRules();

            public static DialRules CreatetorInstance { get { return instance; } }
        }
        #endregion
    }

	class PhoneNumberFormatter
	{
		public static string FormatURL(string number)
		{
			//return "http://172.31.27.25/Dial.xml?n=" + PhoneNumberFormatter.FormatForDial(number); 
            return PhoneNumberFormatter.FormatForDial(number);
		}

		public static string FormatForDisplay(string number)
		{
			string justNumbers = Regex.Replace(number, @"[^\d]", "");
            PhoneNumber? numberInfo = DialRules.Instance.GetFromNpaNxx(number);
            if(numberInfo.HasValue)
            {
                return numberInfo.Value.StarDialCode+number.Substring(number.Length-4,4);
            }
			return number;
		}

		public static string FormatForDial(string number)
		{
			number = (number.StartsWith("*") ? "*" : "") + Regex.Replace(number, @"[^\d]", "");
            Match isFormatted = Regex.Match(number, @"^\*([1-5]00|957|266|661|348)\d{4}");
			if (!isFormatted.Success)
			{
				number = PhoneNumberFormatter.FormatForDisplay(number);
				if (!number.StartsWith("*"))
				{
					if (number.Length == 10) /* don't add this to internal numbers */
					{
						//us/local number, needs both 9 and the 1 
						number = "91" + number;
					}
					else if (number.StartsWith("1") && number.Length == 11)
					{
						//us/local number that needs just the 9
						number = "9" + number;
					}
					else if (number.Length > 10 && !number.StartsWith("91"))
					{
						//this is an interantional number
						if (!number.StartsWith("9011"))
						{
							number = "9011" + number;
						}
					}
				}
			}
			return number;
		}

		public static void FormatForSearch(string phoneNumber, ref string phone1, ref string phone2, ref string phone3)
		{
			phoneNumber = Regex.Replace(phoneNumber, @"[^\d]", "");
			phone3 = phoneNumber.Substring(3, 4);
            PhoneNumber? numberInfo = DialRules.Instance.GetFromStar(phoneNumber);
            if (numberInfo.HasValue)
            {
                phone1 = numberInfo.Value.Npa;
                phone2 = numberInfo.Value.Nxx;
            }
		}
	}
}
