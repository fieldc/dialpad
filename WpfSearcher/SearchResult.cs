using System;
using System.Diagnostics;
using System.Text.RegularExpressions;

namespace WpfSearcher
{
	public class SearchResult
	{
		string name;
		string phone;
		string formattedPhone;
		string department;
		string location;
		string email;
		string url;
		private static Object countLock = new Object();
		
		
		public SearchResult(string searchResultLine) 
		{
			this.name = this.phone = this.department = this.location = this.email = this.url = "N/A";
			searchResultLine = searchResultLine.Trim(new char[] { '"' });
			
			string[] items = searchResultLine.Split(new string[1] { "\"," },StringSplitOptions.None);
			foreach (string item in items)
			{
				string cleanItem = item.Trim();
				if (cleanItem.StartsWith("Last_Name:"))
				{
					//Match results = Regex.Match(responseStr, @"\s*searchResults\s*=\s*\[(?<data>.*)\];.*YAHOO.example.Basic", RegexOptions.ExplicitCapture);
					Match info = Regex.Match(cleanItem, "href='(?<url>.*)'>(?<last>.*)</a>", RegexOptions.ExplicitCapture);
					if (info.Success)
					{
						this.name = info.Groups["last"].Value;
						this.url = info.Groups["url"].Value;
					}
				}
				else if (cleanItem.StartsWith("First_MI:"))
				{
					Match info = Regex.Match(cleanItem, "First_MI:\\\"(?<name>.*)\\\"", RegexOptions.ExplicitCapture);
					if (info.Success)
						this.name = info.Groups["name"].Value.Trim() +" "+this.name.Trim();
					else
					{
						info = Regex.Match(cleanItem, "First_MI:\\\"(?<name>.*)", RegexOptions.ExplicitCapture);
						if (info.Success)
							this.name = info.Groups["name"].Value.Trim() + " " + this.name.Trim();
					}

				}
				else if (cleanItem.StartsWith("Phone:"))
				{
					Match info = Regex.Match(cleanItem, "Phone:\\\"(?<phone>.*)\\\"", RegexOptions.ExplicitCapture);
					if (!info.Success)
					{
						info = Regex.Match(cleanItem, "Phone:\\\"(?<phone>.*)", RegexOptions.ExplicitCapture);
					}
					if (info.Success)
					{
						this.phone = info.Groups["phone"].Value;
						if (!this.phone.Contains(","))
						{
							this.phone = this.phone.Trim();
						}
						else
						{
							string[] numbers = this.phone.Split(new char[] { ',' });
							this.phone = numbers[0].Trim();
						}

						if (this.phone.Contains("X"))
						{
							string[] numbers = this.phone.Split(new char[] { 'X' });
							this.phone = numbers[0].Trim();
						}
					}
				}
				else if (cleanItem.StartsWith("Dept:"))
				{
					Match info = Regex.Match(cleanItem, "Dept:\\\"(?<dept>.*)\\\"", RegexOptions.ExplicitCapture);
					if (info.Success)
						this.department = info.Groups["dept"].Value;
					else
					{
						info = Regex.Match(cleanItem, "Dept:\\\"(?<dept>.*)", RegexOptions.ExplicitCapture);
						if (info.Success)
							this.department = info.Groups["dept"].Value;
					}
				}
				else if (cleanItem.StartsWith("Location:"))
				{
					Match info = Regex.Match(cleanItem, "Location:\\\"(?<loc>.*)\\\"", RegexOptions.ExplicitCapture);
					if (info.Success)
						this.location = info.Groups["loc"].Value;
					else
					{
						info = Regex.Match(cleanItem, "Location:\\\"(?<loc>.*)", RegexOptions.ExplicitCapture);
						if (info.Success)
							this.location = info.Groups["loc"].Value;
					}
				}
				else if (cleanItem.StartsWith("Email:"))
				{
					Match info = Regex.Match(cleanItem, "^Email:\\\"<a href='mailto:(?<email>[^'>]*)'>.*$", RegexOptions.ExplicitCapture);
					if(info.Success)
						this.email = info.Groups["email"].Value.Trim();
				}
			}

			/*
			 * string[] columns = searchResultLine.Split(new char[1] { '~' });
			this.url = columns[1].Trim();
			this.name = columns[2].Replace("&nbsp;", "").Trim() + " " + columns[0].Trim();
			if (!columns[3].Contains(","))
			{
				this.phone = columns[3].Trim();
			}
			else 
			{
				string[] numbers = columns[3].Split(new char[] { ',' });
				this.phone = numbers[0].Trim();
			}

			if (this.phone.Contains("X"))
			{
				string[] numbers = this.phone.Split(new char[] { 'X' });
				this.phone = numbers[0].Trim();
			}

			this.department = Regex.Match(columns[4], "^<span title=(?<dept>[^>]*)>.*$").Groups["dept"].Value.Trim();
			this.location = columns[5].Trim();
			this.email = Regex.Match(columns[6], "^<a href=mailto:(?<email>[^>]*)>.*$").Groups["email"].Value.Trim();
			 */
			Debug.WriteLine(String.Format("Name: {0} Phone: {1} Dept: {2} Location: {3} Email: {4} Url: {5}", this.Name, this.Phone, this.Department, this.Location, this.Email,this.Url));
		}

		public SearchResult(string pageHTML,bool wholePage)
		{

			//Match businessPhone = null;
			//Match nameMatch = Regex.Match(pageHTML, "<b>Full Name:</b></td>\\s*<td class=ps_body width=33% valign=top><span class=\"redcopybold\">(?<name>[^<]*)\\s*</span>\\s*</td>");
            Match nameMatch = Regex.Match(pageHTML, "<b>Full Name:</b></td>\\s*<td width=33% ><div class=\"bold red\">(?<name>[^<]*)\\s*</div>\\s*</td>");
			Match urlMatch = Regex.Match(pageHTML, "directReports.jsp.nylid=(?<empId>[a-z0-9]+)&vgnextoid=96180a38da835110VgnVCM1000001c3a1dacRCRD");
			//Match urlMatch =	Regex.Match(pageHTML, "<a href=\"#\" onclick=\"window.open\\('/NYLINT/PeopleSearch/PopUp/1,5323,(?<empId>[a-z0-9]+)-dr,00.html','directreport'");

			Match phoneMatch = Regex.Match(pageHTML, "<div class=\"bold\">Phone:</div></td>\\s*<td>\\s*(?<phone>[0-9\\- \\(\\)]+)");
			if (!phoneMatch.Success)
			{
				//we might have a preferred phone and business phone
				phoneMatch = Regex.Match(pageHTML, "<b>Preferred Phone:</b></td>\\s*<td\\s*class=ps_body width=33% valign=top>\\s*(?<phone>[0-9\\- \\(\\)]+)\\s*(&nbsp;)?</td>");
				//businessPhone = Regex.Match(pageHTML, "<b>Business Phone:</b></td>\\s*<td width=\"33%\" valign=\"top\" class=\"ps_body\">\\s*(?<phone>[0-9\\- \\(\\)]+)\\s*(&nbsp;)?</td>");
			}
			Match emailMatch = Regex.Match(pageHTML, "<div class=\"bold\">Email:</div></td><td><a href=\"mailto:(?<email>[^\"]*)");
            Match deptMatch = Regex.Match(pageHTML, "<div class=\"bold\">Department:</div></td>\\s*<td>\\s*(?<department>[^<]*)</td>");
            Match locationMatch = Regex.Match(pageHTML, "<div class=\"bold\">Location:</div></td>\\s*<td>\\s*(?<location>[^<]*)</td>");
			

			this.name = nameMatch.Groups["name"].Value.Replace("&nbsp;"," ").Trim();
			this.phone = phoneMatch.Groups["phone"].Value.Trim();
			this.department = deptMatch.Groups["department"].Value.Trim();
			this.location = locationMatch.Groups["location"].Value.Trim();
			this.email = emailMatch.Groups["email"].Value.Trim();
			if (urlMatch.Success)
			{
				this.url = "/intranet/jsp/others/peopleSearchResults.jsp?vgnextoid=96180a38da835110VgnVCM1000001c3a1dacRCRD&nylid=" + urlMatch.Groups["empId"].Value.Trim();
			}
			else
			{
				this.url = "";
			}
			Debug.WriteLine(String.Format("Name: {0} Phone: {1} Dept: {2} Location: {3} Email: {4} Url: {5}", this.Name, this.Phone, this.Department, this.Location, this.Email,this.Url));
		}

		public static int Compare(SearchResult a, SearchResult b)
		{
			return String.Compare(a.Name, b.Name);
		}

		public override string  ToString()
		{
 			 return name;
		}
		public string Name { get { return name; } }
		public string Phone 
		{ 
			get 
			{
				if (string.IsNullOrEmpty(this.formattedPhone))
				{
					this.formattedPhone = PhoneNumberFormatter.FormatForDisplay(this.phone); 
				}
				return formattedPhone; 
			} 
		}

		public string PhoneURL { 
			get { 
				return PhoneNumberFormatter.FormatURL(this.phone);
			} 
		}

		public string Department { get { return department; } }
		public string Location { get { return location; } }
		public string Email { get { return email; } }
		public string EmailURL { get { return "mailto://"+email; } }
		public string Url { get { return (!string.IsNullOrEmpty(this.url))?"http://..."+url:"";  } }
		public string ToolTipString { get { return String.Format("{0}{5}{1}{5}{2}{5}{3}{5}{4}{5}", name, phone, email, department, location,System.Environment.NewLine); } }

	}
}

