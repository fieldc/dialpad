using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Reflection;
using System.Text;
using System.Xml;
using System.Xml.Serialization;
using dotnet2Drawing = System.Drawing;

namespace CiscoPhone
{
	public class CiscoIPPhoneExecute
	{

		public Dictionary<int, Item> items;

		public CiscoIPPhoneExecute()
		{
			this.items = new Dictionary<int, Item>();
		}

		public string Format()
		{
			string formatted = "<CiscoIPPhoneExecute>";
			foreach (Item myItem in this.items.Values)
			{
				formatted += "<ExecuteItem Priority=\"" + myItem.Priority.ToString() + "\" URL=\"" + myItem.URL + "\"/>";
			}
			formatted += "</CiscoIPPhoneExecute>";
			return formatted;
		}

		public struct Item
		{
			int priority;
			string url;

			public int Priority { get { return this.priority; } set { this.priority = value; } }
			public string URL { get { return this.url; } set { this.url = value; } }

			public Item(int priority, string url)
			{
				this.priority = priority;
				this.url = url;
			}
		}
	}

	public class IpPhoneActions
	{

		public static string GetKeyCode(string buttonToSend)
		{
			string keyCode = "";
			switch (buttonToSend)
			{
				case "0":
					keyCode = "KeyPad0";
					break;
				case "1":
					keyCode = "KeyPad1";
					break;
				case "2":
					keyCode = "KeyPad2";
					break;
				case "3":
					keyCode = "KeyPad3";
					break;
				case "4":
					keyCode = "KeyPad4";
					break;
				case "5":
					keyCode = "KeyPad5";
					break;
				case "6":
					keyCode = "KeyPad6";
					break;
				case "7":
					keyCode = "KeyPad7";
					break;
				case "8":
					keyCode = "KeyPad8";
					break;
				case "9":
					keyCode = "KeyPad9";
					break;
				case "*":
					keyCode = "KeyPadStar";
					break;
				case "#":
					keyCode = "KeyPadPound";
					break;
				default:
					keyCode = buttonToSend;
					break;
				/*
				case Keys.Down:
					keyCode = "NavDwn";
					break;
				case Keys.Up:
					keyCode = "NavUp";
					break;
				case Keys.Left:
					keyCode = "NavLeft";
					break;
				case Keys.Right:
					keyCode = "NavRight";
					break;
				*/
			}
			
			return keyCode;
		}


		public static void SendButton(string userName, string password, string ipAddress, string button)
		{
			try
			{
				CiscoIPPhoneExecute toExecute = new CiscoIPPhoneExecute();
				string buttonToSend = "";
				if (!button.StartsWith("Key"))
				{
					buttonToSend = IpPhoneActions.GetKeyCode(button);
				}
				else
				{
					buttonToSend = button;
				}
				toExecute.items.Add(0, new CiscoIPPhoneExecute.Item(0, "Key:" + buttonToSend));
				if (buttonToSend == "Info")
				{
					toExecute.items.Add(1, new CiscoIPPhoneExecute.Item(0, "Key:" + buttonToSend));
				}
				IpPhoneActions.SendRequest(userName, password, ipAddress, toExecute);
			}
			catch (Exception ex)
			{
				Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": " + ex.Message);
			}
		}

		public static void SendRequest(string userName, string password, string ipAddress, CiscoIPPhoneExecute toExecute)
		{
			string xml = "XML=" + toExecute.Format();
			byte[] body = Encoding.ASCII.GetBytes(xml);
			NetworkCredential credentials = new NetworkCredential(userName, password);
			HttpWebRequest buttonRequest;

			try
			{
				buttonRequest = (HttpWebRequest)HttpWebRequest.Create("http://" + ipAddress + "/CGI/Execute");
				buttonRequest.ContentType = "application/x-www-form-urlencoded";
				buttonRequest.ContentLength = body.Length;
				buttonRequest.PreAuthenticate = true;
				buttonRequest.KeepAlive = true;
				buttonRequest.Credentials = credentials;
				buttonRequest.Method = "POST";

				Stream requestStream = buttonRequest.GetRequestStream();
				requestStream.Write(body, 0, body.Length);
				requestStream.Close();

				WebResponse response = buttonRequest.GetResponse();
				response.Close();
			}
			catch (WebException e)
			{
				Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": " + e.Message);
			}
			catch (Exception ex)
			{
				Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": " + ex.Message);
			}

		}


		public static dotnet2Drawing.Bitmap GetScreenShotFromPhone(string username, string password, string ipAddress)
		{
			try
			{
				Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": Making Request: "+DateTime.Now.ToLongTimeString());
				MemoryStream ms = new MemoryStream();
				HttpWebRequest screenShotRequest = (HttpWebRequest)HttpWebRequest.Create("http://" + ipAddress + "/CGI/Screenshot");
				screenShotRequest.KeepAlive = true;
				screenShotRequest.PreAuthenticate = true;
				screenShotRequest.Credentials = new NetworkCredential(username, password);

				WebResponse response = screenShotRequest.GetResponse();
				Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": Request Complete: " + DateTime.Now.ToLongTimeString());
				
				if (!response.ContentType.ToLower().Contains("image/bmp"))
				{
					Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": Processing CIP Image");
					byte[] buffer = new byte[4096];
					int readBytes = 0;
					Stream readFrom = response.GetResponseStream();
					while ((readBytes = readFrom.Read(buffer, 0, buffer.Length)) != 0)
					{
						ms.Write(buffer, 0, readBytes);
					}
					
					response.Close();
					ms.Position = 0;
					Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": Converting to bitmap: " + DateTime.Now.ToLongTimeString());
					return CipImage.FromStream(ms).ToBitmap();
				}
				else
				{
					Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": Processing BMP image");
					return (dotnet2Drawing.Bitmap)dotnet2Drawing.Bitmap.FromStream(response.GetResponseStream());
				}
			}
			catch (WebException e)
			{
				Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": " + e.Message);
			}
			catch (Exception ex)
			{
				Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": " + ex.Message);
			}

			return (dotnet2Drawing.Bitmap)null;
		}
	}

	[XmlRoot("CiscoIPPhoneImage")]
	public class CipImage
	{
		private CipImage() { ;}
		public static CipImage FromFile(string fileName)
		{
			FileInfo fi = new FileInfo(fileName);
			XmlSerializer serializer = new XmlSerializer(typeof(CipImage));
			return (CipImage)serializer.Deserialize(fi.OpenRead());
		}

		public static CipImage FromStream(Stream stream)
		{
			try
			{
				Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": Starting Serializer: " + DateTime.Now.ToLongTimeString());
				XmlSerializer serializer = new XmlSerializer(typeof(CipImage));
				return (CipImage)serializer.Deserialize(stream);
			}
			catch (Exception e)
			{
				Debug.WriteLine(e.Message);
				return (CipImage)null;
			}
		}

		// (script-fu-round-button 0 "0" 16  "TahomaBold"  "6d6d6d" "b5b5b5" "f4f4f4" "d6d6d6" "5b5b5b" "c9ffc3" 4 4 2 1 1 1 1)
		public dotnet2Drawing.Bitmap ToBitmap()
		{
			try
			{
				Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": Starting BitMap: " + DateTime.Now.ToLongTimeString());
				dotnet2Drawing.Bitmap bm = new dotnet2Drawing.Bitmap(this.Width, this.Height);
				dotnet2Drawing.Color[] colors = new dotnet2Drawing.Color[4];
				colors[3] = dotnet2Drawing.Color.Black;
				colors[2] = dotnet2Drawing.Color.FromArgb(Convert.ToInt32(0x7f), Convert.ToInt32(0xaa), Convert.ToInt32(0x75));
				colors[1] = dotnet2Drawing.Color.FromArgb(Convert.ToInt32(0x99), Convert.ToInt32(0xcc), Convert.ToInt32(0x99));
				colors[0] = dotnet2Drawing.Color.FromArgb(Convert.ToInt32(0xbf), Convert.ToInt32(0xff), Convert.ToInt32(0xbf));

				this.Data = this.Data.Trim();
				//loop counters for x,y mapping of pixel
				int y = 0, x = 0;
				for (int i = 0; i < this.Data.Length; i += 2)
				{
					string hexDigits = this.Data.Substring(i, 2);
					byte imgByte = Convert.ToByte(hexDigits, 16);
					//acording to doc bytes are mapped reversed 
					byte upackedByte1 = (byte)(imgByte & (byte)3);
					byte upackedByte2 = (byte)((imgByte & (byte)12) >> 2);
					byte upackedByte3 = (byte)((imgByte & (byte)48) >> 4);
					byte upackedByte4 = (byte)((imgByte & (byte)192) >> 6);
					bm.SetPixel(x, y, colors[upackedByte1]);
					bm.SetPixel(x + 1, y, colors[upackedByte2]);
					bm.SetPixel(x + 2, y, colors[upackedByte3]);
					bm.SetPixel(x + 3, y, colors[upackedByte4]);
					x += 4;
					if (x >= this.Width)
					{
						++y;
						x = 0;
					}
				}

				Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": Bitmap Complete: " + DateTime.Now.ToLongTimeString());
				return bm;
			}
			catch (Exception ex)
			{
				Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": " + ex.Message);
			}
			return (dotnet2Drawing.Bitmap)null;
		}

		
		[XmlElement("LocationX")]
		public int LocationX { get; set; }
		[XmlElement("LocationY")]
		public int LocationY { get; set; }
		[XmlElement("Height")]
		public int Height { get; set; }
		[XmlElement("Width")]
		public int Width { get; set; }
		[XmlElement("Depth")]
		public int Depth { get; set; }
		[XmlElement("Data")]
		public string Data { get; set; }


	}

}
