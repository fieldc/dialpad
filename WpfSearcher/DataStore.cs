using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Collections;
using System.Collections.Specialized;
using System.Windows;
using System.Xml;
using System.Xml.Serialization;
using System.IO;
using System.Diagnostics;
using System.Net;


namespace WpfSearcher
{
	[Serializable]
	[XmlRoot("DataStore", Namespace = "")]
	public class DataStore : Hashtable, IXmlSerializable
	{
		private DataStore()
		{
			try
			{
				string dir = System.Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + "/NYL Voice Apps/Searcher";
				string fileName = dir + "/settings.xml";
				if (File.Exists(fileName))
				{
					FileStream fs = new FileStream(fileName, FileMode.Open);
					XmlReaderSettings xmlsettings = new XmlReaderSettings();
					xmlsettings.IgnoreComments = true;
					xmlsettings.IgnoreWhitespace = true;
					xmlsettings.IgnoreProcessingInstructions = true;
					xmlsettings.CloseInput = true;
					((IXmlSerializable)this).ReadXml(XmlReader.Create(fs, xmlsettings));
				}
				else
				{
					if (!Directory.Exists(dir))
						Directory.CreateDirectory(dir);
				}
			}
			catch (Exception ex)
			{
				Debug.WriteLine(ex.Message);
			}
		}

		public void Save()
		{
			try
			{
				string dir = System.Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + "/NYL Voice Apps/Searcher";

				string fileName = dir + "/settings.xml";
				XmlWriterSettings xmlsettings = new XmlWriterSettings();
				xmlsettings.CloseOutput = true;
				xmlsettings.Indent = true;
				FileStream fs;

				if (File.Exists(fileName))
				{
					fs = new FileStream(fileName, FileMode.Truncate);
				}
				else
				{
					fs = new FileStream(fileName, FileMode.Create);
				}
				((IXmlSerializable)this).WriteXml(XmlWriter.Create(fs, xmlsettings));
			}
			catch (Exception ex)
			{
				Debug.WriteLine(ex.Message);
			}
		}

		/// <summary>
		/// Overide default accessor to make this an externally readonly hashtable
		/// </summary>
		/// <param name="configParam">which value is needed</param>
		/// <returns>config object</returns>
		public override object this[object item]
		{
			get
			{
				return base[item];
			}

			set
			{
				if (this.ContainsKey(item))
				{
					this.Remove(item);
				}
				this.Add(item, value);
			}
		}

		[XmlElement("SaveScreenPosition")]
		public bool SaveScreenPosition
		{
			get
			{
				if (!this.ContainsKey("SaveScreenPosition"))
					return false;
				else
					return (bool)this["SaveScreenPosition"];
			}
			set
			{
				if (this.ContainsKey("SaveScreenPosition"))
					this.Remove("SaveScreenPosition");

				this.Add("SaveScreenPosition", value);
			}
		}

		[XmlElement("SettingsLastPosition")]
		public Point SettingsLastPosition
		{
			get
			{
				if (!this.ContainsKey("SettingsLastPosition"))
					return new Point(Double.MinValue,Double.MinValue);
				else
					return (Point)this["SettingsLastPosition"];
			}
			set
			{
				if (this.ContainsKey("SettingsLastPosition"))
					this.Remove("SettingsLastPosition");
				this.Add("SettingsLastPosition", value);
			}
		}
		[XmlElement("DialPadLastPosition")]
		public Point DialPadLastPosition
		{
			get
			{
				if (!this.ContainsKey("DialPadLastPosition"))
					return new Point(Double.MinValue,Double.MinValue);
				else
					return (Point)this["DialPadLastPosition"];
			}
			set
			{
				if (this.ContainsKey("DialPadLastPosition"))
					this.Remove("DialPadLastPosition");
				this.Add("DialPadLastPosition", value);
			}
		}

		[XmlElement("SearcherLastPosition")]
		public Point SearcherLastPosition
		{
			get
			{
				if (!this.ContainsKey("SearcherLastPosition"))
					return new Point(Double.MinValue,Double.MinValue);
				else
					return (Point)this["SearcherLastPosition"];
			}
			set
			{
				if (this.ContainsKey("SearcherLastPosition"))
					this.Remove("SearcherLastPosition");
				this.Add("SearcherLastPosition", value);
			}
		}

		[XmlElement("DiscoverPhones")]
		public bool DiscoverPhones
		{
			get
			{
				if (!this.ContainsKey("DiscoverPhones"))
					return false;
				else
					return (bool)this["DiscoverPhones"];
			}
			set
			{
				if (this.ContainsKey("DiscoverPhones"))
					this.Remove("DiscoverPhones");
				this.Add("DiscoverPhones", value);

			}
		}

		[XmlElement("IpAddress")]
		public string IpAddress
		{
			get
			{
				if (!this.ContainsKey("IpAddress"))
					return "";
				else
					return (string)this["IpAddress"];
			}
			set
			{
				if (this.ContainsKey("IpAddress"))
					this.Remove("IpAddress");

				IPAddress holder;
				if (IPAddress.TryParse(value, out holder))
				{
					this.Add("IpAddress", value);
				}
			}
		}

		[XmlElement("UserId")]
		public string UserId
		{
			get
			{
				if (!this.ContainsKey("UserId"))
					return "";
				else
					return (string)this["UserId"];
			}
			set
			{
				if (this.ContainsKey("UserId"))
					this.Remove("UserId");

				this.Add("UserId", value);
			}
		}

		[XmlElement("Password")]
		public string Password
		{
			get
			{
				if (!this.ContainsKey("Password"))
					return "p124356";
				else
					return (string)this["Password"];
			}
			set
			{
				if (this.ContainsKey("Password"))
					this.Remove("Password");

				this.Add("Password", value);
			}
		}

		#region Properties
		/// <summary>
		/// Gets the Instance of the Configration object
		/// </summary>
		public static DataStore Instance
		{
			get { return Creator.CreatetorInstance; }
		}
		#endregion

		#region Singleton Creator

		/// <summary>
		/// This is our singleton creator class, uses a readonly field to garuntee a sinlge instance 
		/// off the class
		/// </summary>
		private sealed class Creator
		{
			/// <summary>
			/// Readonly fields can only be initialized during object construction or on declaration
			/// so we are garunteed this only happens once
			/// </summary>
			private static readonly DataStore instance = new DataStore();

			/// <summary>
			/// Gets the Configuration Instance
			/// </summary>
			public static DataStore CreatetorInstance
			{
				get
				{
					return instance;
				}
			}
		}
		#endregion

		#region IXmlSerializable Members

		System.Xml.Schema.XmlSchema IXmlSerializable.GetSchema()
		{
			throw new NotImplementedException();
		}

		void IXmlSerializable.ReadXml(System.Xml.XmlReader reader)
		{
			PointConverter pc = new PointConverter();
			
			reader.ReadStartElement();
			if (String.CompareOrdinal(reader.Name, "SaveScreenPosition") == 0)
			{
				this.SaveScreenPosition = Boolean.Parse(reader.ReadElementContentAsString());
			}

			if (String.CompareOrdinal(reader.Name, "SettingsLastPosition") == 0 && !reader.IsEmptyElement)
			{
				try
				{
					this.SettingsLastPosition = (Point)pc.ConvertFromString(reader.ReadElementContentAsString());
				}
				catch (OverflowException)
				{
					this.SettingsLastPosition = new Point(double.MinValue, double.MinValue);
				}
			}
			else if (String.CompareOrdinal(reader.Name, "SettingsLastPosition") == 0 && reader.IsEmptyElement)
			{
				this.SettingsLastPosition = new Point(Double.MinValue,Double.MinValue);
				reader.ReadElementContentAsString();
			}

			if (String.CompareOrdinal(reader.Name, "DialPadLastPosition") == 0 && !reader.IsEmptyElement)
			{
				try
				{
					this.DialPadLastPosition = (Point)pc.ConvertFromString(reader.ReadElementContentAsString());
				}
				catch (OverflowException)
				{
					this.DialPadLastPosition = new Point(double.MinValue, double.MinValue);
				}
			}
			else if (String.CompareOrdinal(reader.Name, "DialPadLastPosition") == 0 && reader.IsEmptyElement)
			{
				this.DialPadLastPosition = new Point(Double.MinValue,Double.MinValue);
				reader.ReadElementContentAsString();
			}

			if (String.CompareOrdinal(reader.Name, "SearcherLastPosition") == 0 && !reader.IsEmptyElement)
			{
				try
				{
					this.SearcherLastPosition = (Point)pc.ConvertFromString(reader.ReadElementContentAsString());
				}
				catch (OverflowException)
				{
					this.SearcherLastPosition = new Point(double.MinValue, double.MinValue);
				}
			}
			else if (String.CompareOrdinal(reader.Name, "SearcherLastPosition") == 0 && reader.IsEmptyElement)
			{
				this.SearcherLastPosition = new Point(Double.MinValue,Double.MinValue);
				reader.ReadElementContentAsString();
			}

			if (String.CompareOrdinal(reader.Name, "DiscoverPhones") == 0)
			{
				this.DiscoverPhones = Boolean.Parse(reader.ReadElementContentAsString());
			}

			if (String.CompareOrdinal(reader.Name, "IpAddress") == 0)
			{
				IPAddress holder;
				string ip = reader.ReadElementContentAsString();
				if (IPAddress.TryParse(ip, out holder))
				{
					this.Add("IpAddress", ip);
				}
			}

			if (String.CompareOrdinal(reader.Name, "UserId") == 0)
			{
				try
				{
					string userId = reader.ReadElementContentAsString();
					this.Add("UserId", userId);
				}
				catch (Exception ex)
				{
					Debug.WriteLine(ex.Message);
					this.Add("UserId", "");
				}

			}

			if (String.CompareOrdinal(reader.Name, "Password") == 0)
			{
				try
				{
					string password = reader.ReadElementContentAsString();
					this.Add("Password", password);
				}
				catch (Exception ex)
				{
					Debug.WriteLine(ex.Message);
					this.Add("Password", "");
				}
				
			}

			reader.ReadEndElement();
			reader.Close();
		}

		void IXmlSerializable.WriteXml(System.Xml.XmlWriter writer)
		{
			PointConverter pc = new PointConverter();
			writer.WriteStartElement("DataStore");
			writer.WriteElementString("SaveScreenPosition", this.SaveScreenPosition.ToString());
			writer.WriteElementString("SettingsLastPosition", pc.ConvertToString(this.SettingsLastPosition));
			writer.WriteElementString("DialPadLastPosition", pc.ConvertToString(this.DialPadLastPosition));
			writer.WriteElementString("SearcherLastPosition", pc.ConvertToString(this.SearcherLastPosition));
			writer.WriteElementString("DiscoverPhones", this.DiscoverPhones.ToString());
			writer.WriteElementString("IpAddress", this.IpAddress);
			writer.WriteElementString("UserId", this.UserId);
			writer.WriteElementString("Password", this.Password);
			writer.WriteEndElement();
			writer.Close();	
		}

		#endregion
	}
}
