using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using WinPcap;


namespace WpfSearcher
{
	class CDPListener
	{
		private static Dictionary<string,string> phonesFound;
		private Thread discoveryThread;
		private bool shutDown;
		public event EventHandler PhonesFound;
		
		public CDPListener(bool runAutodiscovery)
		{
			phonesFound = new Dictionary<string,string>(StringComparer.Ordinal);
			this.RunAutoDiscovery(runAutodiscovery);
		}

		public void RunAutoDiscovery(bool runAutodiscovery)
		{
			if (runAutodiscovery)
			{
				if (discoveryThread == null)
				{
					discoveryThread = new Thread(new ThreadStart(this.StartDiscovery));
					Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": Starting Thread");
					this.shutDown = false;
					this.discoveryThread.Start();
				}
			}
			else
			{
				this.ShutDown = true;
			}
		}

		public static bool HaveAttachedPhones
		{
			get
			{
				lock (phonesFound)
				{
					return phonesFound.Count > 0 ? true : false;
				}
			}
		}
		public static Dictionary<string, string> AttachedPhones
		{
			get
			{
				Dictionary<string, string> phonesToReturn = new Dictionary<string, string>(StringComparer.Ordinal);
				lock (phonesFound)
				{
					foreach (KeyValuePair<string, string> kvp in phonesFound)
					{
						phonesToReturn.Add(kvp.Key, kvp.Value);
					}
				}
				return phonesToReturn;
			}
		}

		public void AddPhoneManually(string ip)
		{
			lock (phonesFound)
			{
				bool firePhonesFoundEvent = phonesFound.Count > 0 ? false : true;
				string name = "Manually Added";
				if (phonesFound.ContainsKey(name) || phonesFound.ContainsValue(ip))
					return;

				phonesFound.Add(name,ip);
				if (firePhonesFoundEvent)
				{
					this.OnPhonesFound();
				}
			}
		}

		public void RemoveManuallyAddedPhone()
		{
			lock (phonesFound)
			{
				string name = "Manually Added";
				if (phonesFound.ContainsKey(name))
				{
					phonesFound.Remove(name);
				}
			}
		}

		private void StartDiscovery()
		{
			Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": Thread Started");

			Capture.PcapIf interfaceList = new Capture.PcapIf();
			IntPtr pcapPtr = IntPtr.Zero;
			Capture.BpfProgram bpfProgram = new Capture.BpfProgram();
			StringBuilder errorString = new StringBuilder(Capture.PCAP_ERRBUF_SIZE);

			try
			{
				int result = Capture.pcap_findalldevs_ex("rpcap://", IntPtr.Zero, ref interfaceList, errorString);
				Capture.PcapIf interfaceToUse = new Capture.PcapIf();


				if (result == 0 && interfaceList.next != IntPtr.Zero)
				{
					bool finished = false;
					Capture.PcapIf currInterface = (Capture.PcapIf)Marshal.PtrToStructure(interfaceList.next, interfaceList.GetType());
					do
					{
						Debug.WriteLine(String.Format("currInterface: {0}  Desc: {1}  ", currInterface.name, currInterface.description));
						if (currInterface.description.Contains("Ethernet"))
						{
							Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": Using Interface: " + currInterface.description);
							interfaceToUse = currInterface;
							finished = true;
						}
						else
						{
							if (currInterface.next == IntPtr.Zero)
								finished = true;
							else
								currInterface = (Capture.PcapIf)Marshal.PtrToStructure(currInterface.next, interfaceList.GetType());
						}

					} while (!finished);
				}
				else
				{
					throw new Exception(errorString.ToString());
				}

				if (string.IsNullOrEmpty(interfaceToUse.name))
				{
					throw new Exception("Failed to find interface to use");
				}

				pcapPtr = Capture.pcap_open_live(interfaceToUse.name.Replace("rpcap://", ""), 65536, 0, 5000, errorString);
				if (pcapPtr == IntPtr.Zero)
				{
					throw new Exception(errorString.ToString());
				}

				if (errorString.Length > 0)
				{
					Debug.WriteLine(errorString.ToString());
				}

				//prepare filter
				string filter = "ether host 01:00:0c:cc:cc:cc";
				if (Capture.pcap_compile(pcapPtr, ref bpfProgram, filter, 1, 0) < 0)
				{
					throw new Exception(Capture.pcap_geterr(pcapPtr));
				}

				if (Capture.pcap_setfilter(pcapPtr, ref bpfProgram) < 0)
				{
					throw new Exception("Failed to set filter");
				}


				Capture.PcapPkthdr header = new Capture.PcapPkthdr();
				result = 0;
				IntPtr headerPtr = IntPtr.Zero;
				IntPtr dataPtr = IntPtr.Zero;

				while ((result = Capture.pcap_next_ex(pcapPtr, ref headerPtr, ref dataPtr)) >= 0)
				{
					if (result == 0) /* Timeout elapsed */
					{
						if (this.shutDown)
						{
							break;
						}
						continue;
					}

					if (result == 1)
					{
						Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": Recieved packet");
						header = (Capture.PcapPkthdr)Marshal.PtrToStructure(headerPtr, header.GetType());
						Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": PacketLength: " + header.len);
						byte[] data = new byte[header.len];
						Marshal.Copy(dataPtr, data, 0, data.Length);
						CDPPacket info = CDPPacket.Parse(data);
						if (info.IsPhone)
						{
							lock (phonesFound)
							{
								bool firePhonesFoundEvent = phonesFound.Count > 0 ? false : true;
								if (phonesFound.ContainsKey(info.DeviceName))
									phonesFound.Remove(info.DeviceName);

								if (phonesFound.ContainsValue(info.Address))
								{
									foreach (KeyValuePair<string, string> kvp in phonesFound)
									{
										if (kvp.Value.Equals(info.Address, StringComparison.Ordinal))
										{
											phonesFound.Remove(kvp.Key);
											break;
										}
									}
								}
								phonesFound.Add(info.DeviceName, info.Address);
								if (firePhonesFoundEvent)
								{
									this.OnPhonesFound();
								}
							}
						}
					}
					else
					{
						Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": FAIL BITCH: " + result.ToString());
					}
				}
			}
			catch (ThreadInterruptedException) { Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": Thread Interupted"); ;}
			catch (Exception ex)
			{
				Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": Error Ocurred: " + ex.Message);
			}
			finally
			{
				Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": Thread Exiting");
				if (interfaceList.next != IntPtr.Zero)
				{
					Capture.pcap_freealldevs(ref interfaceList);
				}

				if (bpfProgram.bf_len != 0)
				{
					Capture.pcap_freecode(ref bpfProgram);
				}

				if (pcapPtr != IntPtr.Zero)
				{
					Capture.pcap_close(pcapPtr);
				}
			}
		}

		private void OnPhonesFound()
		{
			if (this.PhonesFound != null)
			{
				PhonesFound(this, new EventArgs());
			}
		}

		public bool ShutDown
		{
			get { return shutDown; }
			set {
				shutDown = value;
				if (this.discoveryThread != null)
				{
					this.discoveryThread.Interrupt();
					this.discoveryThread.Join(1500);
					this.discoveryThread = null;
				}
			}
		}
	}
}
