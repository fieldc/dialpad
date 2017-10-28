using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;



namespace WpfSearcher
{
	public class Searcher
	{
		public Searcher()
		{
			
		}

		public List<SearchResult> Search(string searchText)
		{
			string req = "";
			if (string.IsNullOrEmpty(searchText))
			{
				throw new ArgumentNullException("searchText must contain something");
			}

			//now figure out if we are searching for a name or a number
			if (!Regex.IsMatch(searchText, @"[a-zA-Z]{1,}"))
			{
				//Search for a phone number if there are 2+ digits
				string phoneNumber = Regex.Replace(searchText, @"[^\d]", "");

				string phone1 = "", phone2 = "", phone3 = "";
				///Now we need to figure out what numbers we are searching for rules are
				///if it is a [1-5]00XXXX number => phone3=XXXX
				///if it is a NXX-XXXX number => phone2=NXX,phone3=NXXX
				///if it is a NPA-NXX-XXXX number => phone1=NPA,phone2=NXX,phone3=XXXX
				///if the number is less than 7 digits we start filling from the
				///back i.e. 35000 => phone2=3, phone3=5000 unless it is specified as (NPA)....
				///i.e. (212)5 will => phone1=212,phone2=5
				if (searchText.StartsWith("("))
				{
					phone1 = phoneNumber.Substring(0, Math.Min(3, phoneNumber.Length));
					if (phoneNumber.Length > 3)
					{
						phone2 = phoneNumber.Substring(3, Math.Min(3, phoneNumber.Length - 3));
						if (phoneNumber.Length > 6)
						{
							phone3 = phoneNumber.Substring(6, Math.Min(4, phoneNumber.Length - 6));
						}
					}
				}
				else
				{
					if (Regex.IsMatch(phoneNumber, @"\*?[1-5]00\d{4}"))
					{
						phoneNumber = phoneNumber.TrimStart(new char[] { '*' });
						//internal dial maps to phone3=>XXXX
						PhoneNumberFormatter.FormatForSearch(phoneNumber, ref phone1, ref phone2, ref phone3);
					}
					else
					{
						phone3 = phoneNumber.Substring(phoneNumber.Length - Math.Min(4, phoneNumber.Length), Math.Min(4, phoneNumber.Length));
						if (phoneNumber.Length > 4)
						{
							phone2 = phoneNumber.Substring(phoneNumber.Length - Math.Min(7, phoneNumber.Length), Math.Min(3, phoneNumber.Length - 4));
							if (phoneNumber.Length > 7)
							{
								phone1 = phoneNumber.Substring(phoneNumber.Length - Math.Min(10, phoneNumber.Length), Math.Min(3, phoneNumber.Length - 7));
							}
						}
					}
				}
				req = "firstname=&lastname=&department=0&division=0&location=0&gocode=&room=&title=0&specialrole=0&languages=0&phone1=" + phone1 + "&phone2=" + phone2 + "&phone3=" + phone3 + "&costcenter=0&acf2id=&Submit=Search&searchtype=advanced";
			}
			else
			{
				//we have a name, if it is two+ words it is firstname lastname else lastname
				string firstName = "", lastName = "";

				if (Regex.IsMatch(searchText, @"\w{2,}"))
				{
					string[] names = searchText.Split(new char[] { ' ' });
					for (int i = 0; i < names.Length - 1; i++)
					{
						firstName += names[i] + " ";
					}
					lastName = names[names.Length - 1];
				}
				else
				{
					lastName = searchText;
				}
				firstName = firstName.Trim();
				lastName = lastName.Trim();
				if (String.IsNullOrEmpty(firstName) && String.IsNullOrEmpty(lastName))
				{
					throw new ArgumentNullException("Invalid Name Arguments");
				}
				req = "firstname=" + firstName + "&lastname=" + lastName + "&department=0&division=0&location=0&gocode=&room=&title=0&specialrole=0&languages=0&phone1=&phone2=&phone3=&costcenter=0&acf2id=&button=Search";
			}
			req = "vgnextoid=96180a38da835110VgnVCM1000001c3a1dacRCRD&" + req;
			Debug.WriteLine(req);

			byte[] body = Encoding.ASCII.GetBytes(req);
		    string url = "http://.../intranet/jsp/others/peopleSearchResults.jsp?";
			List<SearchResult> searchResults = new List<SearchResult>();

			try
			{
				HttpWebRequest request = (HttpWebRequest)HttpWebRequest.Create(url);
				request.Method = "POST";
				request.ContentType = "application/x-www-form-urlencoded";
				request.ContentLength = body.Length;
				request.KeepAlive = true;
				request.Method = "POST";
				request.Timeout = 15000; //15 sec time out

				Stream requestStream = request.GetRequestStream();
				requestStream.Write(body, 0, body.Length);
				WebResponse response = request.GetResponse();
				string responseStr = (new StreamReader(response.GetResponseStream()).ReadToEnd()).Replace("\r","").Replace("\t","").Replace("\n","");
				
				if (responseStr.Contains("searchResults = "))
				{
					Match results = Regex.Match(responseStr, @"\s*searchResults\s*=\s*\[(?<data>.*)\];.*YAHOO.example.Basic", RegexOptions.ExplicitCapture);
					if (results.Success)
					{
						string match = Regex.Replace(results.Groups["data"].Value,@"\s{1,}"," ").Trim().Trim(new char[2] { '{','}'});
						string[] rows = Regex.Split(match,@"}\s*,\s*{");//  match.Split( .Split(new char[1] { ',' });
						foreach (string row in rows)
						{
							searchResults.Add(new SearchResult(row));
						}
					}
				}
				else
				{
					//single person response, need to parse page
					searchResults.Add(new SearchResult(responseStr,true));
				}
				response.Close();
			}
			catch (WebException wex)
			{
				Debug.WriteLine(wex.Message);
				throw new Exception("Failed to retrieve results", wex);
			}
			catch (Exception ex)
			{
				Debug.WriteLine(ex.Message);
				throw new Exception("Unknown communication error", ex);
			}
			return searchResults;
		}
	}
}
