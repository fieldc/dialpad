using System;
using System.Diagnostics;
using System.Net;
using System.Reflection;
using System.Text;

namespace WpfSearcher
{
	class CDPPacket
	{
		
		const ushort TYPE_DEVICE_ID = 0x0001;
		const ushort TYPE_ADDRESS = 0x0002;
		const ushort TYPE_PORT_ID = 0x0003;
		const ushort TYPE_CAPABILITIES = 0x0004;
		const ushort TYPE_IOS_VERSION = 0x0005;
		const ushort TYPE_PLATFORM = 0x0006;
		const ushort TYPE_IP_PREFIX = 0x0007;
		const ushort TYPE_VTP_MGMT_DOMAIN = 0x0009;
		const ushort TYPE_NATIVE_VLAN = 0x000a;
		const ushort TYPE_DUPLEX = 0x000b;
		const ushort TYPE_VOIP_VLAN = 0x000e;
		const ushort TYPE_POWER_CONSUMPTION = 0x0010;
		const ushort TYPE_TRUST_BITMAP = 0x0012;
		const ushort TYPE_UNTRUSTED_PORT_COS = 0x0013;
		

		const ushort PROTO_TYPE_NLPID = 1;
		const ushort PROTO_TYPE_IEEE_802_2 = 2;


		const ulong PROTO_ISO_CLNS=0x81;
		const ulong PROTO_IPV4 = 0xCC;
		const ulong PROTO_IPv6 = 0xAAAA030000000800;
		const ulong PROTO_DECNET = 0xAAAA030000006003;
		const ulong PROTO_APPLETALK = 0xAAAA03000000809B;
		const ulong PROTO_IPX = 0xAAAA030000008137;
		const ulong PROTO_BANYAN_VINES = 0xAAAA0300000080c4;
		const ulong PROTO_XNS = 0xAAAA030000000600;
		const ulong PROTO_APOLLO=0xAAAA030000008019;

		/// Header info
		
		private byte version; 
		private byte ttl; 
		private ushort checksum; 
		private string portId;
		private UInt32 capabilites;
		private string iosVersion;
		private string platform;
		private string deviceName;
		private int vtpMgmtDomain;
		private int nativeVlan;
		private int duplex;
		private int voiceVlan;
		private int trustBitMap;
		private int unstrustedPortCos;
		private int powerConsumption;
		private IPAddress addresses;
		

		private CDPPacket()
		{
			version = 0;
			ttl = 0;
			checksum = 0;
			portId = "";
			capabilites = 0;
			iosVersion = "";
			platform = "";
			deviceName = "";
			vtpMgmtDomain = 0;
			nativeVlan = 0;
			duplex = 0;
			voiceVlan = 0;
			trustBitMap = 0;
			unstrustedPortCos = 0;
			powerConsumption = 0;		
		}

		public static CDPPacket Parse(byte[] packet)
		{
			int currPos = 22;
			CDPPacket pktInfo = new CDPPacket();
			   
			pktInfo.version = packet[currPos]; ++currPos;
			pktInfo.ttl = packet[currPos]; ++currPos;
			pktInfo.checksum = (ushort)(packet[++currPos] + ((ushort)packet[currPos-1] << 8)); ++currPos;
			Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": Parsing Packet");
					
			while (currPos < packet.Length) 
			{
				ushort type = (ushort)(packet[++currPos] + ((ushort)packet[currPos-1] << 8)); ++currPos;
				ushort length = (ushort)((packet[++currPos] + ((ushort)packet[currPos - 1] << 8))); ++currPos;
				ushort valuelength = (ushort)(length - 4); /* subtract len + type fields*/
				
				switch (type)
				{
					case CDPPacket.TYPE_DEVICE_ID:
						pktInfo.deviceName = Encoding.ASCII.GetString(packet, currPos, valuelength);
						Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": TYPE_DEVICE_ID: "+pktInfo.deviceName);
						currPos += valuelength;
						break;

					case CDPPacket.TYPE_ADDRESS:
						uint numAddresses = (uint)(packet[currPos + 3] + ((uint)packet[currPos + 2] << 8) + ((uint)packet[currPos + 1] << 16) + ((uint)packet[currPos] << 24));/* next 4 bytes */
						currPos += 4;
						Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": TYPE_ADDRESS: ");
						Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": \tAddress Count(" + numAddresses.ToString()+")");
						for (ushort addressCounter = 0; addressCounter < numAddresses; addressCounter++)
						{
							ushort protocol = (ushort)packet[currPos]; ++currPos;
							ushort protocolLength = (ushort)packet[currPos]; ++currPos;
							UInt64 protocolCode = 0;
							switch (protocol)
							{
								case CDPPacket.PROTO_TYPE_NLPID:
									//protocol length is always one		
									Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": \tAddress Type: 	PROTO_TYPE_NLPID");		
									protocolCode = Convert.ToUInt64(packet[currPos]); ++currPos;
									break;
								case CDPPacket.PROTO_TYPE_IEEE_802_2:
									Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": \tAddress Type: PROTO_TYPE_IEEE_802_2");
									//protocol length is 3 or 8
									for(int lenCounter=currPos;lenCounter<currPos+protocolLength;++lenCounter)
									{
										protocolCode += (ulong)packet[lenCounter] << (((currPos + protocolLength) - lenCounter) * 8);
									}
									currPos += protocolLength;
									break;
							}
							ushort addressLength = (ushort)(packet[currPos+1] + ((ushort)packet[currPos] << 8)); 
							currPos+=2;
							byte[] addrArray = new byte[addressLength];
							for(int i=currPos;i<currPos+addressLength;i++)
							{
								addrArray[i-currPos]=packet[i];
							}

							if (protocolCode == CDPPacket.PROTO_IPV4)
							{
								pktInfo.addresses = new IPAddress(addrArray);
								Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": \tAddress: " + pktInfo.addresses.ToString());
							}
							else
							{
								Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": Invalid Protocol Code: " +protocol.ToString());
							}

							currPos += addressLength;
						}
						break;
					case CDPPacket.TYPE_PORT_ID:
						pktInfo.portId = Encoding.ASCII.GetString(packet, currPos, valuelength);
						Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": TYPE_PORT_ID: "+pktInfo.portId);
						currPos += valuelength;
						break;
					case CDPPacket.TYPE_CAPABILITIES:
						pktInfo.capabilites = 0;
						for (int lenCounter = currPos; lenCounter < currPos + valuelength; ++lenCounter)
						{
							pktInfo.capabilites += (uint)packet[lenCounter] << (((currPos + valuelength) - lenCounter - 1 /*bit shift len-1 so we don't go off the end*/) * 8);
						}
						Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": TYPE_CAPABILITIES: "+pktInfo.capabilites.ToString());
						currPos += valuelength;
						break;
					case CDPPacket.TYPE_IOS_VERSION:
						pktInfo.iosVersion = Encoding.ASCII.GetString(packet, currPos, valuelength);
						Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": TYPE_IOS_VERSION: " + pktInfo.iosVersion);
						currPos += valuelength;
						break;
					case CDPPacket.TYPE_PLATFORM:
						pktInfo.platform = Encoding.ASCII.GetString(packet, currPos, valuelength);
						Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": TYPE_PLATFORM: " + pktInfo.platform);
						currPos += valuelength;
						break;
					case CDPPacket.TYPE_IP_PREFIX:
						//skip this for now
						//TODO: don't skip this
						Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": Skipping: TYPE_IP_PREFIX");
						currPos += valuelength;
						break;
					case CDPPacket.TYPE_VTP_MGMT_DOMAIN:
						for (int lenCounter = currPos; lenCounter < currPos + valuelength; ++lenCounter)
						{
							pktInfo.vtpMgmtDomain += packet[lenCounter] << (((currPos + valuelength) - lenCounter - 1 /*bit shift len-1 so we don't go off the end*/ ) * 8);
						}
						Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": TYPE_VTP_MGMT_DOMAIN: " + pktInfo.vtpMgmtDomain.ToString());
						currPos += valuelength;
						break;
					case CDPPacket.TYPE_NATIVE_VLAN:
						pktInfo.nativeVlan = 0;
						for (int lenCounter = currPos; lenCounter < currPos + valuelength; ++lenCounter)
						{
							pktInfo.nativeVlan += packet[lenCounter] << (((currPos + valuelength) - lenCounter - 1 /*bit shift len-1 so we don't go off the end*/ ) * 8);
						}
						Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": TYPE_NATIVE_VLAN: " + pktInfo.nativeVlan.ToString());
						currPos += valuelength;
						break;
					case CDPPacket.TYPE_DUPLEX:
						for (int lenCounter = currPos; lenCounter < currPos + valuelength; ++lenCounter)
						{
							pktInfo.duplex += packet[lenCounter] << (((currPos + valuelength) - lenCounter - 1 /*bit shift len-1 so we don't go off the end*/ ) * 8);
						}
						Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": TYPE_DUPLEX: " + pktInfo.duplex.ToString());
						currPos += valuelength;
						break;
					case CDPPacket.TYPE_VOIP_VLAN:
						pktInfo.voiceVlan = 0;
						++currPos; /* Skip Data field flap, not sure what its for */
						--valuelength; //account for skiped Data field
						for (int lenCounter = currPos; lenCounter < currPos + valuelength; ++lenCounter)
						{
							pktInfo.voiceVlan += packet[lenCounter] << (((currPos + valuelength) - lenCounter - 1 /*bit shift len-1 so we don't go off the end*/) * 8);
						}
						Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": TYPE_VOIP_VLAN: " + pktInfo.voiceVlan.ToString());
						currPos += valuelength;
						break;
					case CDPPacket.TYPE_TRUST_BITMAP:
						for (int lenCounter = currPos; lenCounter < currPos + valuelength; ++lenCounter)
						{
							pktInfo.trustBitMap += packet[lenCounter] << (((currPos + valuelength) - lenCounter - 1 /*bit shift len-1 so we don't go off the end*/ ) * 8);
						}
						Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": TYPE_TRUST_BITMAP: " + pktInfo.trustBitMap.ToString());
						currPos += valuelength;
						break;
					case CDPPacket.TYPE_UNTRUSTED_PORT_COS:
						for (int lenCounter = currPos; lenCounter < currPos + valuelength; ++lenCounter)
						{
							pktInfo.unstrustedPortCos += packet[lenCounter] << (((currPos + valuelength) - lenCounter - 1 /*bit shift len-1 so we don't go off the end*/ ) * 8);
						}
						Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": TYPE_UNTRUSTED_PORT_COS: " + pktInfo.unstrustedPortCos.ToString());
						currPos += valuelength;
						break;
					case CDPPacket.TYPE_POWER_CONSUMPTION:
						for (int lenCounter = currPos; lenCounter < currPos + valuelength; ++lenCounter)
						{
							pktInfo.powerConsumption += packet[lenCounter] << (((currPos + valuelength) - lenCounter - 1 /*bit shift len-1 so we don't go off the end*/ ) * 8);
						}
						Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": TYPE_POWER_CONSUMPTION: " + pktInfo.powerConsumption.ToString());
						currPos += valuelength;
						break;
				}
			}

			
			return pktInfo;
		}

		public string Address
		{
			get { return this.addresses.ToString(); } 
		}

		public string DeviceName {
			get { return this.deviceName; }
		}

		public bool IsPhone {
			get { return this.platform.Contains("Cisco IP Phone"); }
		}
	}
}
