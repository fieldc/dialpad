using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
using System.IO;
using Pcap_T = System.IntPtr;
using PcapDumper_T = System.IntPtr;
using BpfUI32Ptr = System.UIntPtr;
using BpfUI32 = System.UInt32;

namespace WinPcap
{
	public class Capture
	{
		//pcap_handler (u_char *user, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data)

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
		public struct TimeVal
		{
			public UInt32 tv_sec; // sec
			public UInt32 tv_usec; // microsec
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
		public struct PcapPkthdr /* pcap_pkt_hdr */
		{
			public TimeVal ts;
			public UInt32 caplen;
			public UInt32 len;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
		public struct BpfInsn /* bpf_insn */
		{
			byte code;
			byte jt;
			byte jf;
			Int32 k;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
		public struct BpfProgram  /* struct bpf_program */
		{
			public UInt32	bf_len;
			public BpfInsn bf_insns;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
		public struct PcapSamp /* pcap_samp */
		{
			public Int32 method;
			public Int32 value;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
		public struct PcapRmtAuth  /* pcap_rmt_auth */
		{
			public Int32 type;
			public string username;
			public string password;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
		public struct InAddr
		{
			// uchar equiv is 2 bytes each. Might have to layoutkind.explicit it
			public byte b1;
			public byte b2;
			public byte b3;
			public byte b4;
			public UInt16 w1;
			public UInt16 w2;
			public UInt64 addr;
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct SockAddr
		{
			public Int16 family;
			public UInt16 port;
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
			public byte[] addr;
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
			public byte[] zero;
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct PcapAddr
		{
			public IntPtr next;
			public IntPtr addr;
			public IntPtr netmask;
			public IntPtr broadaddr;
			public IntPtr dstaddr;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
		public struct PcapIf
		{
			public IntPtr next;
			public string name;
			public string description;
			public IntPtr addresses;
			public uint flags;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
		public struct PcapSendQueue
		{
			public UInt32 maxlen;
			public UInt32 len;
			public string buffer;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
		public struct PcapStat /* pcap_stat */
		{
			/// <summary>
			/// number of packets transited on the network
			/// </summary>
			UInt32 ps_recv;

			/// <summary>
			/// number of packets dropped by the driver
			/// </summary>
			UInt32 ps_drop;

			/// <summary>
			/// drops by interface, not yet supported
			/// </summary>
			UInt32 ps_ifdrop;

			/// <summary>
			/// Win32 specific. number of packets captured, i.e number of packets that are accepted by the filter, 
			/// that find place in the kernel buffer and therefore that actually reach the application. For 
			/// backward compatibility, pcap_stats() does not fill this member, so use pcap_stats_ex() to get it. 
			/// </summary>
			UInt32 bs_capt;
		}


		/// <summary>
		/// Prototype of the callback function that receives the packets. 
		/// </summary>
		/// <remarks>
		/// When pcap_dispatch() or pcap_loop() are called by the user, the packets are passed to the application 
		/// by means of this callback. user is a user-defined parameter that contains the state of the capture 
		/// session, it corresponds to the user parameter of pcap_dispatch() and pcap_loop(). pkt_header is the 
		/// header associated by the capture driver to the packet. It is NOT a protocol header. pkt_data points 
		/// to the data of the packet, including the protocol headers.
		/// </remarks>
		/// <param name="user"></param>
		/// <param name="pktHeader"></param>
		/// <param name="pktData"></param>
		public delegate void PcapHandler(string user, ref PcapPkthdr pktHeader, string pktData);

		/// <summary>
		/// set a flag that will force pcap_dispatch() or pcap_loop() to return rather than looping. 
		/// </summary>
		/// <remarks>
		/// They will return the number of packets that have been processed so far, or -2 if no packets 
		/// have been processed so far. This routine is safe to use inside a signal handler on UNIX or 
		/// a console control handler on Windows, as it merely sets a flag that is checked within the loop. 
		/// The flag is checked in loops reading packets from the OS - a signal by itself will not necessarily 
		/// terminate those loops - as well as in loops processing a set of packets returned by the OS.
		/// 
		/// Note that if you are catching signals on UNIX systems that support restarting system calls after a signal, 
		/// and calling pcap_breakloop() in the signal handler, you must specify, when catching those signals,		/// that system calls should NOT be restarted by that signal. Otherwise, if the signal interrupted a call 
		/// reading packets in a live capture, when your signal handler returns after calling pcap_breakloop(), 
		/// the call will be restarted, and the loop will not terminate until more packets arrive and the call completes.
		/// 
		/// Note:
		/// pcap_next() will, on some platforms, loop reading packets from the OS; that loop will not necessarily 
		/// be terminated by a signal, so pcap_breakloop() should be used to terminate packet processing even if 
		/// pcap_next() is being used. pcap_breakloop() does not guarantee that no further packets will be processed 
		/// by pcap_dispatch() or pcap_loop() after it is called; at most one more packet might be processed. 
		/// If -2 is returned from pcap_dispatch() or pcap_loop(), the flag is cleared, so a subsequent call will 
		/// resume reading packets. If a positive number is returned, the flag is not cleared, so a subsequent 
		/// call will return -2 and clear the flag. 
		/// </remarks>
		/// <param name="pcap_tInfo"></param>
		[DllImport("wpcap.dll", EntryPoint = "pcap_breakloop", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern void pcap_breakloop(Pcap_T info);


		/// <summary>
		/// close the files associated with p and deallocates resources.
		/// </summary>
		/// <seealso cref="pcap_open_live()"/>
		/// <seealso cref="pcap_open_offline()"/>
		/// <seealso cref="pcap_open_dead()"/>
		/// <param name="p"></param>
		[DllImport("wpcap.dll", EntryPoint = "pcap_close", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern void pcap_close(Pcap_T p);


		/// <summary>
		/// Compile a packet filter, converting an high level filtering expression (see Filtering expression syntax) in a program that can be interpreted by the kernel-level filtering engine.
		/// </summary>
		/// <remarks>pcap_compile() is used to compile the string str into a filter program. program is a pointer to a 
		/// bpf_program struct and is filled in by pcap_compile(). optimize controls whether optimization on the 
		/// resulting code is performed. netmask specifies the IPv4 netmask of the network on which packets are being 
		/// captured; it is used only when checking for IPv4 broadcast addresses in the filter program. If the netmask 
		/// of the network on which packets are being captured isn't known to the program, or if packets are being 
		/// captured on the Linux "any" pseudo-interface that can capture on more than one network, a value of 0 can be 
		/// supplied; tests for IPv4 broadcast addreses won't be done correctly, but all other tests in the filter program 
		/// will be OK. A return of -1 indicates an error in which case pcap_geterr() may be used to display the error text.
		/// 
		/// See also: pcap_open_live(), pcap_setfilter(), pcap_freecode(), pcap_snapshot() </remarks>
		/// <param name="p"></param>
		/// <param name="?"></param>
		/// <returns></returns>
		[DllImport("wpcap.dll", EntryPoint = "pcap_compile", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern Int32 pcap_compile(Pcap_T p, ref BpfProgram fp, string str, Int32 optimize, BpfUI32 netmask);

		/// <summary>
		/// Compile a packet filter without the need of opening an adapter. This function converts an high level filtering expression (see Filtering expression syntax) in a program that can be interpreted by the kernel-level filtering engine.
		/// </summary>
		/// <remarks>
		/// pcap_compile_nopcap() is similar to pcap_compile() except that instead of passing a pcap structure, one passes the snaplen and linktype explicitly. It is intended to be used for compiling filters for direct BPF usage, without necessarily having called pcap_open(). A return of -1 indicates an error; the error text is unavailable. (pcap_compile_nopcap() is a wrapper around pcap_open_dead(), pcap_compile(), and pcap_close(); the latter three routines can be used directly in order to get the error text for a compilation error.)
		/// 
		/// Look at the Filtering expression syntax section for details on the str parameter.
		/// See also:  pcap_open_live(), pcap_setfilter(), pcap_freecode(), pcap_snapshot() 
		/// </remarks>
		/// <param name="snaplen_arg"></param>
		/// <param name="linktype_arg"></param>
		/// <param name="?"></param>
		/// <returns></returns>
		[DllImport("wpcap.dll", EntryPoint = "pcap_compile_nopcap", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern Int32 pcap_compile_nopcap(Int32 snaplen_arg, Int32 linktype_arg, ref BpfProgram program, string buf, Int32 optimize, BpfUI32 mask);

		/// <summary>
		/// Accept a set of strings (host name, port, ...), and it returns the complete source string according to the new format (e.g. 'rpcap://1.2.3.4/eth0').
		/// </summary>
		/// <remarks>
		/// This function is provided in order to help the user creating the source string according to the new format. An unique source string is used in order to make easy for old applications to use the remote facilities. Think about tcpdump, for example, which has only one way to specify the interface on which the capture has to be started. However, GUI-based programs can find more useful to specify hostname, port and interface name separately. In that case, they can use this function to create the source string before passing it to the pcap_open() function.
		/// 
		/// Parameters:
		///    	source,: 	a user-allocated buffer that will contain the complete source string wen the function returns.
		///    		  The source will start with an identifier according to the new Source Specification Syntax .
		///	   This function assumes that the allocated buffer is at least PCAP_BUF_SIZE bytes.
		///	    	type,: 	its value tells the type of the source we want to create. It can assume the values defined in the Source identification Codes .
		///	    	    	host,: 	an user-allocated buffer that keeps the host (e.g. "foo.bar.com") we want to connect to. It can be NULL in case we want to open an interface on a local host.
		///	    	    	    	port,: 	an user-allocated buffer that keeps the network port (e.g. "2002") we want to use for the RPCAP protocol. It can be NULL in case we want to open an interface on a local host.
		///	    	    	    	   name,: 	an user-allocated buffer that keeps the interface name we want to use (e.g. "eth0"). It can be NULL in case the return string (i.e. 'source') has to be used with the pcap_findalldevs_ex(), which does not require the interface name.
		///	    	    	    	   errbuf,: 	a pointer to a user-allocated buffer (of size PCAP_ERRBUF_SIZE) that will contain the error message (in case there is one).
		///	    	    	    	   
		/// Returns:
		///     '0' if everything is fine, '-1' if some errors occurred. The string containing the complete source is returned in the 'source' variable.
		///Warning:
		///    If the source is longer than PCAP_BUF_SIZE, the excess characters are truncated. 
		/// </remarks>
		/// <param name="source"></param>
		/// <param name="type"></param>
		/// <param name="?"></param>
		/// <returns></returns>
		[DllImport("wpcap.dll", EntryPoint = "pcap_createsrcstr", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern Int32 pcap_createsrcstr(StringBuilder source, Int32 type, string host, string port, string name, StringBuilder errbuf);

		/// <summary>
		/// Size of PCAP_BUF_SIZE
		/// </summary>
		public const int PCAP_BUF_SIZE = 1024;
		/// <summary>
		/// Size of errbuf
		/// </summary>
		public const int PCAP_ERRBUF_SIZE = 256;

		/// <summary>
		/// BSD loopback encapsulation; the link layer header is a 4-byte field, in 
		/// host byte order, containing a PF_ value from socket.h for the network-layer 
					/// protocol of the packet. Note that ``host byte order'' is the byte order of the 
		 			/// machine on which the packets are captured, and the PF_ values are for the OS of 
				  /// the machine on which the packets are captured; if a live capture is being done, ``host byte order'' 
				  /// is the byte order of the machine capturing the packets, and the PF_ values are those of the OS of 
				  /// the machine capturing the packets, but if a ``savefile'' is being read, the byte order and PF_ values
		/// are not necessarily those of the machine reading the capture file.
		/// </summary>
		public const int DLT_NULL=0;
		/// <summary>
		/// Ethernet (10Mb, 100Mb, 1000Mb, and up)
		/// </summary>
		public const int DLT_EN10MB = 1;
		/// <summary>
		/// IEEE 802.5 Token Ring
		/// </summary>
		public const int DLT_IEEE802 = 6;
		/// <summary>
		/// ARCNET
		/// </summary>
		public const int DLT_ARCNET = 7;
		/// <summary>
		/// SLIP; the link layer header contains, in order:
		/// 1. a 1-byte flag, which is 0 for packets received by the machine and 1 for packets sent by the machine;
		/// 2. a 1-byte field, the upper 4 bits of which indicate the type of packet, as per RFC 1144:
		///	0x40: an unmodified IP datagram (TYPE_IP);
		///	0x70: an uncompressed-TCP IP datagram (UNCOMPRESSED_TCP), with that byte being the first byte of the raw IP header on the wire, containing the connection number in the protocol field;
		///	0x80: a compressed-TCP IP datagram (COMPRESSED_TCP), with that byte being the first byte of the compressed TCP/IP datagram header;
		/// 3. for UNCOMPRESSED_TCP, the rest of the modified IP header, and for COMPRESSED_TCP, the compressed TCP/IP datagram header;
		/// 4. for a total of 16 bytes; the uncompressed IP datagram follows the header.
		/// </summary>
		public const int DLT_SLIP = 8;
		/// <summary>
		/// PPP; if the first 2 bytes are 0xff and 0x03, it's PPP in HDLC-like framing, with the PPP 
		/// header following those two bytes, otherwise it's PPP without framing, and the packet 
		/// begins with the PPP header.
		/// </summary>
		public const int DLT_PPP = 9;
		/// <summary>
		/// FDDI
		/// </summary>
		public const int DLT_FDDI = 10;
		/// <summary>
		/// RFC 1483 LLC/SNAP-encapsulated ATM; the packet begins with an IEEE 802.2 LLC header.
		/// </summary>
		public const int DLT_ATM_RFC1483 = 11;
		/// <summary>
		/// raw IP; the packet begins with an IP header.
		/// </summary>
		public const int DLT_RAW = 12;
		/// <summary>
		/// PPP in HDLC-like framing, as per RFC 1662, or Cisco PPP with HDLC framing, as 
		/// per section 4.3.1 of RFC 1547; the first byte will be 0xFF for PPP in HDLC-like framing,
		/// and will be 0x0F or 0x8F for Cisco PPP with HDLC framing.
		/// </summary>
		public const int DLT_PPP_SERIAL = 50;
		/// <summary>
		/// PPPoE; the packet begins with a PPPoE header, as per RFC 2516.
		/// </summary>
		public const int DLT_PPP_ETHER = 51;
		/// <summary>
		/// Cisco PPP with HDLC framing, as per section 4.3.1 of RFC 1547.
		/// </summary>
		public const int DLT_C_HDLC = 104;
		/// <summary>
		/// IEEE 802.11 wireless LAN
		/// </summary>
		public const int DLT_IEEE802_11 = 105;
		/// <summary>
		/// Frame Relay
		/// </summary>
		public const int DLT_FRELAY = 107;
		/// <summary>
		/// OpenBSD loopback encapsulation; the link layer header is a 4-byte field, 
		/// in network byte order, containing a PF_ value from OpenBSD's socket.h 
		/// for the network-layer protocol of the packet. Note that, if a ``savefile'' 
		/// is being read, those PF_ values are not necessarily those of the machine
		/// reading the capture file.
		/// </summary>
		public const int DLT_LOOP = 108;
		/// <summary>
		/// Linux "cooked" capture encapsulation; the link layer header contains, in order:
		///	a 2-byte "packet type", in network byte order, which is one of:
		///		1. packet was sent to us by somebody else
		///		2. packet was broadcast by somebody else
		///		3. packet was multicast, but not broadcast, by somebody else
		///		4. packet was sent by somebody else to somebody else
		///		5. packet was sent by us
		///			a 2-byte field, in network byte order, containing a Linux ARPHRD_ value for the link layer device type;
		///			a 2-byte field, in network byte order, containing the length of the link layer address of the sender of the packet (which could be 0);
		///			an 8-byte field containing that number of bytes of the link layer header (if there are more than 8 bytes, only the first 8 are present);
		///			2-byte field containing an Ethernet protocol type, in network byte order, or containing 1 for Novell 802.3 frames without an 802.2 LLC header or 4 for frames beginning with an 802.2 LLC header.
		/// </summary>
		public const int DLT_LINUX_SLL = 113;
		/// <summary>
		///  Apple LocalTalk; the packet begins with an AppleTalk LLAP header.
		/// </summary>
		public const int DLT_LTALK = 114;
		/// <summary>
		/// OpenBSD pflog; the link layer header contains, in order:
		///	a 4-byte PF_ value, in network byte order;
		///	a 16-character interface name;
		///	a 2-byte rule number, in network byte order;
		///	a 2-byte reason code, in network byte order, which is one of:
		///		1. match
		///		2. bad offset
		///		3. fragment
		///		4. short
		///		5. normalize
		///		6. memory -a 2-byte action code, in network byte order, which is one of:
		///		7. passed
		///		8. dropped
		///		9. scrubbed
		///	a 2-byte direction, in network byte order, which is one of:
		///		1. incoming or outgoing
		///		2. incoming
		///		3. outgoing
		/// </summary>
		public const int DLT_PFLOG = 117;
		/// <summary>
		/// Prism monitor mode information followed by an 802.11 header.
		/// </summary>
		public const int DLT_PRISM_HEADER = 119;
		/// <summary>
		/// RFC 2625 IP-over-Fibre Channel, with the link-layer header being the Network_Header as described in that RFC.
		/// </summary>
		public const int DLT_IP_OVER_FC = 122;
		/// <summary>
		/// SunATM devices; the link layer header contains, in order:
		///	a 1-byte flag field, containing a direction flag in the uppermost bit, which is set for packets 
		///	transmitted by the machine and clear for packets received by the machine, and a 4-byte traffic 
		///	type in the low-order 4 bits, which is one of:
		///		1. raw traffic
		///		2. LANE traffic
		///		3. LLC-encapsulated traffic
		///		4. MARS traffic
		///		5. IFMP traffic
		///		6. ILMI traffic
		///		7. Q.2931 traffic
		///			a 1-byte VPI value;
		///			a 2-byte VCI field, in network byte order.
		/// </summary>
		public const int DLT_SUNATM = 123;
		/// <summary>
		/// link-layer information followed by an 802.11 header - 
		/// see http://www.shaftnet.org/~pizza/software/capturefrm.txt for a 
		/// description of the link-layer information.
		/// </summary>
		public const int DLT_IEEE802_11_RADIO = 127;
		/// <summary>
		/// ARCNET, with no exception frames, reassembled packets rather than raw frames, 
		/// and an extra 16-bit offset field between the destination host and type bytes.
		/// </summary>
		public const int DLT_ARCNET_LINUX = 129;
		/// <summary>
		/// Linux-IrDA packets, with a DLT_LINUX_SLL header followed by the IrLAP header.
		/// </summary>
		public const int DLT_LINUX_IRDA = 144;

		/// <summary>
		/// Return the link layer of an adapter.
		/// </summary>
		/// <remarks>
		/// returns the link layer type; link layer types it can return include:
		/// See DLT_ Constants
		/// </remarks>
		/// <see cref="pcap_list_datalinks(), pcap_set_datalink(), pcap_datalink_name_to_val()"/>
		/// <param name="p"></param>
		/// <returns></returns>
		[DllImport("wpcap.dll", EntryPoint = "pcap_datalink", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern Int32 pcap_datalink(Pcap_T p);


		/// <summary>
		/// Translates a data link type name, which is a DLT_ name with the DLT_ removed, 
		/// to the corresponding data link type value. The translation is case-insensitive. 
		/// -1 is returned on failure.
		/// </summary>
		/// <param name="name">Name to translate i.e. IEEE802 => DLT_IEEE802</param>
		/// <returns></returns>
		[DllImport("wpcap.dll", EntryPoint = "pcap_datalink_name_to_val", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern Int32 pcap_datalink_name_to_val(string name);

		/// <summary>
		/// Translates a data link type value to a short description of that
		/// data link type. NULL is returned on failure.
		/// </summary>
		[DllImport("wpcap.dll", EntryPoint = "pcap_datalink_val_to_description", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern string pcap_datalink_val_to_description(Int32 dlt);

		/// <summary>
		/// Translates a data link type value to the corresponding data link type name
		/// </summary>
		/// <returns>Name of DLT_ type NULL on failure</returns>
		[DllImport("wpcap.dll", EntryPoint = "pcap_datalink_val_to_name", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern string pcap_datalink_val_to_name(Int32 dlt);



		/// <summary>
		/// Collect a group of packets.
		/// </summary>
		/// <remarks> is used to collect and process packets. cnt specifies the maximum number 
		/// of packets to process before returning. This is not a minimum number; when reading a 
		/// live capture, only one bufferful of packets is read at a time, so fewer than cnt 
		/// packets may be processed. A cnt of -1 processes all the packets received in one buffer
		/// when reading a live capture, or all the packets in the file when reading a ``savefile''. 
		/// callback specifies a routine to be called with three arguments: a u_char pointer which is 
		/// passed in from pcap_dispatch(), a const struct pcap_pkthdr pointer, and a const u_char pointer 
		/// to the first caplen (as given in the struct pcap_pkthdr a pointer to which is passed to the 
		/// callback routine) bytes of data from the packet (which won't necessarily be the entire packet; 
		/// to capture the entire packet, you will have to provide a value for snaplen in your call to 
		/// pcap_open_live() that is sufficiently large to get all of the packet's data - a value of 65535 
		/// should be sufficient on most if not all networks).
		///  
		/// The number of packets read is returned. 0 is returned if no packets were read from a live 
		/// capture (if, for example, they were discarded because they didn't pass the packet filter, or if, 
		/// on platforms that support a read timeout that starts before any packets arrive, the timeout expires 
		/// before any packets arrive, or if the file descriptor for the capture device is in non-blocking mode 
		/// and no packets were available to be read) or if no more packets are available in a ``savefile.'' 
		/// A return of -1 indicates an error in which case pcap_perror() or pcap_geterr() may be used to display
		/// the error text. A return of -2 indicates that the loop terminated due to a call to pcap_breakloop()
		/// before any packets were processed. If your application uses pcap_breakloop(), make sure that you 
		/// explicitly check for -1 and -2, rather than just checking for a return value &lt; 0.
		/// 
		/// Note:  when reading a live capture, pcap_dispatch() will not necessarily return when the read times out; 
		/// on some platforms, the read timeout isn't supported, and, on other platforms, the timer doesn't start 
		/// until at least one packet arrives. This means that the read timeout should NOT be used in, for example, 
		/// an interactive application, to allow the packet capture loop to ``poll'' for user input periodically, 
		/// as there's no guarantee that pcap_dispatch() will return after the timeout expires.
		/// </remarks>
		/// <see cref="pcap_loop(), pcap_next(), pcap_open_live(), pcap_open_offline(), pcap_handler "/>
		/// <param name="p"></param>
		/// <param name="cnt"></param>
		/// <param name="callback"></param>
		/// <param name="user"></param>
		/// <returns></returns>
		[DllImport("wpcap.dll", EntryPoint = "pcap_dispatch", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern Int32 pcap_dispatch(Pcap_T p, Int32 cnt, PcapHandler callback, string user);


		/// <summary>
		/// Save a packet to disk.
		/// </summary
		/// <remarks>outputs a packet to the "savefile" opened with pcap_dump_open(). Note that its 
		/// calling arguments are suitable for use with pcap_dispatch() or pcap_loop(). 
		/// If called directly, the user parameter is of type pcap_dumper_t as returned by pcap_dump_open().
		/// </remarks>
		/// <see cref="pcap_dump_open(), pcap_dump_close(), pcap_dispatch(), pcap_loop()"/>
		/// <param name="user"></param>
		/// <param name="?"></param>
		[DllImport("wpcap.dll", EntryPoint = "pcap_dump", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern void pcap_dump(string user, ref PcapPkthdr h, string sp);


		/// <summary>
		/// Save a packet to disk.
		/// </summary
		/// <remarks>outputs a packet to the "savefile" opened with pcap_dump_open(). Note that its 
		/// calling arguments are suitable for use with pcap_dispatch() or pcap_loop(). 
		/// If called directly, the user parameter is of type pcap_dumper_t as returned by pcap_dump_open().
		/// </remarks>
		/// <see cref="pcap_dump_open(), pcap_dump_close(), pcap_dispatch(), pcap_loop()"/>
		/// <param name="user"></param>
		/// <param name="?"></param>
		[DllImport("wpcap.dll", EntryPoint = "pcap_dump", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern void pcap_dump(PcapDumper_T dumper, ref PcapPkthdr h, string sp);


		/// <summary>
		/// Closes a savefile.
		/// </summary>
		/// <see cref="pcap_dump_open(), pcap_dump()"/>
		/// <returns>
		/// return the standard I/O stream of the 'savefile' opened by pcap_dump_open().
		/// </returns>
		[DllImport("wpcap.dll", EntryPoint = "pcap_dump_file", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern IntPtr pcap_dump_file(PcapDumper_T p);


		/// <summary>
		/// Closes a packet capture data file, know as a savefile.
		/// </summary>
		/// <remarks>
		/// The pcap_dump_close subroutine closes a packet capture data file, known as the savefile, 
		/// that was opened using the pcap_dump_open subroutine.
		/// </remarks>
		/// <param name="p"></param>
		[DllImport("wpcap.dll", EntryPoint = "pcap_dump_close", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern void pcap_dump_close(PcapDumper_T p);

		/// <summary>
		/// Flushes the output buffer to the ``savefile,'' so that any packets written with pcap_dump() but 
		/// not yet written to the ``savefile'' will be written. -1 is returned on error, 0 on success.
		/// </summary>
		/// <param name="p"></param>
		/// <returns>-1 is returned on error, 0 on success.</returns>
		[DllImport("wpcap.dll", EntryPoint = "pcap_dump_flush", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern int pcap_dump_flush(PcapDumper_T p);



		/// <summary>
		/// Return the file position for a "savefile".
		/// </summary>
		/// <remarks>
		/// pcap_dump_ftell() returns the current file position for the "savefile", representing the
		/// number of bytes written by pcap_dump_open() and pcap_dump() . -1 is returned on error.
		/// </remarks>
		/// <see cref="pcap_dump_open(), pcap_dump()"/>   
		/// <returns>-1 is returned on error</returns>
		[DllImport("wpcap.dll", EntryPoint = "pcap_dump_ftell", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern Int64 pcap_dump_ftell(PcapDumper_T p);



		/// <summary>
		/// Open a file to write packets.
		/// </summary>
		/// <remarks>
		/// is called to open a "savefile" for writing. The name "-" in a synonym for 
		/// stdout. NULL is returned on failure. p is a pcap struct as returned by pcap_open_offline() or 
		/// pcap_open_live(). fname specifies the name of the file to open. Alternatively, you may call 
		/// pcap_dump_fopen() to write data to an existing open stream fp. Note that on Windows, that 
		/// stream should be opened in binary mode. If NULL is returned, pcap_geterr() can be used to 
		/// get the error text.
		/// </remarks>
		/// <see cref="pcap_dump_close(), pcap_dump()"/> 
		/// <returns></returns>
		[DllImport("wpcap.dll", EntryPoint = "pcap_dump_open", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern PcapDumper_T pcap_dump_open(Pcap_T p, string fname);

		[DllImport("wpcap.dll", EntryPoint = "pcap_dump_open", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern PcapDumper_T pcap_dump_open(Pcap_T p, Stream fname);

		/// <summary>
		/// [deprecated] Return the standard stream of an offline capture.
		/// </summary>
		/// <remarks>
		/// returns the standard I/O stream of the "savefile", if a "savefile" was opened 
		/// with pcap_open_offline(), or NULL, if a network device was opened with pcap_open_live().
		/// 
		/// Deprecated:    Due to incompatibilities between the C Runtime (CRT) used to compile WinPcap 
		/// and the one used by WinPcap-based applications, this function may return an invalid FILE 
		/// pointer, i.e. a descriptor that causes all the standard I/O stream functions 
		/// (ftell, fseek, fclose...) to fail. The function is still available for backwards 
		/// binary compatibility, only.
		/// </remarks>
		/// <see cref="pcap_open_offline(), pcap_open_live()"/>  
		/// <param name="p"></param>
		/// <returns></returns>
		[DllImport("wpcap.dll", EntryPoint = "pcap_file", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		[Obsolete]
		public static extern IntPtr pcap_file(Pcap_T p);

		/// <summary>
		///Construct a list of network devices that can be opened with pcap_open_live().
		/// </summary>
		///<remarks>
		/// that there may be network devices that cannot be opened with pcap_open_live()
		/// by the process calling pcap_findalldevs(), because, for example, that process 
		/// might not have sufficient privileges to open them for capturing; if so, those 
		/// devices will not appear on the list.) alldevsp is set to point to the first element 
		/// of the list; each element of the list is of type pcap_if_t, -1 is returned on failure, 
		/// in which case errbuf is filled in with an appropriate error message; 0 is returned on success.
		///</remarks>
		///<see cref="pcap_freealldevs(), pcap_open_live(), pcap_lookupdev(), pcap_lookupnet()"/>
		///<see cref="PcapIf"/>
		/// <returns>-1 is returned on failure, 0 is returned on success</returns>
		[DllImport("wpcap.dll", EntryPoint = "pcap_findalldevs", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern Int32 pcap_findalldevs(ref PcapIf alldevsp, StringBuilder errbuf);

		/// <summary>
		///Create a list of network devices that can be opened with pcap_open().
		///</summary>
		///<remarks>
		///This function is a superset of the old 'pcap_findalldevs()', which is obsolete, 
		///and which allows listing only the devices present on the local machine. Vice versa, 
		///pcap_findalldevs_ex() allows listing the devices present on a remote machine as well. 
		///Additionally, it can list all the pcap files available into a given folder. Moreover, 
		///pcap_findalldevs_ex() is platform independent, since it relies on the standard pcap_findalldevs() 
		///to get addresses on the local machine.
		///
		///In case the function has to list the interfaces on a remote machine, it opens a new control 
		///connection toward that machine, it retrieves the interfaces, and it drops the connection. 
		///However, if this function detects that the remote machine is in 'active' mode, the connection 
		///is not dropped and the existing socket is used.
		///
		///The 'source' is a parameter that tells the function where the lookup has to be done and 
		///it uses the same syntax of the pcap_open().
		///
		///Differently from the pcap_findalldevs(), the interface names (pointed by the alldevs->name and 
		///the other ones in the linked list) are already ready to be used in the pcap_open() call. Vice versa, 
		///the output that comes from pcap_findalldevs() must be formatted with the new pcap_createsrcstr() 
		///before passing the source identifier to the pcap_open().
		///
		///The error message is returned in the 'errbuf' variable. An error could be due to several reasons:
		///
		///    * libpcap/WinPcap was not installed on the local/remote host
		///    * the user does not have enough privileges to list the devices / files
		///    * a network problem
		///    * the RPCAP version negotiation failed
		///    * other errors (not enough memory and others).
		///
		///Warning:
		///    There may be network devices that cannot be opened with pcap_open() by the process calling pcap_findalldevs(), because, for example, that process might not have sufficient privileges to open them for capturing; if so, those devices will not appear on the list.
		///
		///    The interface list must be deallocated manually by using the pcap_freealldevs(). 
		///    
		/// </remarks>
		/// <param name="source">
		///	a string that keeps the 'source localtion', according to the new WinPcap syntax. This source will 
		///	be examined looking for adapters (local or remote) (e.g. source can be 'rpcap://' for 
		///	local adapters or 'rpcap://host:port' for adapters on a remote host) or pcap files 
		///	(e.g. source can be 'file://c:/myfolder/'). The strings that must be prepended to the 'source' in 
		///	order to define if we want local/remote adapters or files is defined in the new Source Specification Syntax .
		/// </param>
		/// <param name="auth">
		///	a pointer to a pcap_rmtauth structure. This pointer keeps the information required 
		///	to authenticate the RPCAP connection to the remote host. This parameter is not meaningful in
		///	case of a query to the local host: in that case it can be NULL.
		/// </param>
		/// <param name="alldevs">
		///	a 'struct pcap_if_t' pointer, which will be properly allocated inside this function. 
		///	When the function returns, it is set to point to the first element of the interface 
		///	list; each element of the list is of type 'struct pcap_if_t'.
		/// </param>
		/// <param name="errbuf">a pointer to a user-allocated buffer (of size PCAP_ERRBUF_SIZE) that will contain the error message (in case there is one).</param>
		/// <returns>'0' if everything is fine, '-1' if some errors occurred. The list of the devices is returned in the 'alldevs' variable. When the function returns correctly, 'alldevs' cannot be NULL. In other words, this function returns '-1' also in case the system does not have any interface to list. </returns>
		[DllImport("wpcap.dll", EntryPoint = "pcap_findalldevs_ex", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern int pcap_findalldevs_ex(string source, ref PcapRmtAuth auth, ref PcapIf alldevs, StringBuilder errbuf);

		[DllImport("wpcap.dll", EntryPoint = "pcap_findalldevs_ex", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern int pcap_findalldevs_ex(string source,IntPtr setToNull, ref PcapIf alldevs, StringBuilder errbuf);



		/// <summary>
		///Free an interface list returned by pcap_findalldevs().
		///</summary>
		///<remarks>
		///pcap_freealldevs() is used to free a list allocated by pcap_findalldevs().
		///</remarks>
		///<see cref="pcap_findalldevs() "/>
		/// <param name="alldevsp"></param>
		[DllImport("wpcap.dll", EntryPoint = "pcap_freealldevs", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern void pcap_freealldevs(ref PcapIf alldevsp);



		/// <summary>
		///Free a filter.
		///</summary>
		///<remarks>
		///	pcap_freecode() is used to free up allocated memory pointed to by a bpf_program struct 
		///	generated by pcap_compile() when that BPF program is no longer needed, for example
		///	after it has been made the filter program for a pcap structure by a call to pcap_setfilter().
		///</remarks>
		///<see cref="pcap_compile(), pcap_compile_nopcap()"/>
		[DllImport("wpcap.dll", EntryPoint = "pcap_freecode", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern void pcap_freecode(ref BpfProgram fp);



		/// <summary>
		///return the error text pertaining to the last pcap library error.
		///
		///Note:
		///    the pointer Return will no longer point to a valid error message string after the pcap_t passed to it is closed; you must use or copy the string before closing the pcap_t.
		///
		///See also:
		///    pcap_perror() 
		/// </summary>
		/// <param name="p"></param>
		/// <returns></returns>
		[DllImport("wpcap.dll", EntryPoint = "pcap_geterr", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern string pcap_geterr(Pcap_T p);



		/// <summary>
		///Return the handle of the event associated with the interface p.
		///
		///This event can be passed to functions like WaitForSingleObject() or WaitForMultipleObjects() to wait until the driver's buffer contains some data without performing a read.
		///
		///We disourage the use of this function because it is not portable.
		///
		///See also:
		///    pcap_open_live() 
		/// </summary>
		/// <param name="p"></param>
		/// <returns></returns>
		[DllImport("wpcap.dll", EntryPoint = "pcap_getevent", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern IntPtr pcap_getevent(Pcap_T p);




		/// <summary>
		///	Get the "non-blocking" state of an interface.
		///
		///pcap_getnonblock() returns the current "non-blocking" state of the capture descriptor; it always returns 0 on "savefiles". If there is an error, -1 is returned and errbuf is filled in with an appropriate error message.
		///
		///See also:
		///    pcap_setnonblock() 
		/// </summary>
		/// <param name="p"></param>
		/// <param name="errbuf"></param>
		/// <returns></returns>
		[DllImport("wpcap.dll", EntryPoint = "pcap_getnonblock", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern Int32 pcap_getnonblock(Pcap_T p, StringBuilder errbuf);




		/// <summary>
		/// returns true if the current savefile uses a different byte order than the current system.
		/// </summary>
		/// <param name="p"></param>
		/// <returns></returns>
		[DllImport("wpcap.dll", EntryPoint = "pcap_is_swapped", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern Int32 pcap_is_swapped(Pcap_T p);



		/// <summary>
		/// Returns a pointer to a string giving information about the version of the libpcap library being used; note that it contains more information than just a version number.
		/// </summary>
		[DllImport("wpcap.dll", EntryPoint = "pcap_lib_version", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern string pcap_lib_version();



		/// <summary>
		///list datalinks
		///
		///pcap_list_datalinks() is used to get a list of the supported data link types of the interface associated with the pcap descriptor. pcap_list_datalinks() allocates an array to hold the list and sets *dlt_buf. The caller is responsible for freeing the array. -1 is returned on failure; otherwise, the number of data link types in the array is returned.
		///
		///See also:
		///    pcap_datalink(), pcap_set_datalink(), pcap_datalink_name_to_val() 
		/// </summary>
		/// <param name="p"></param>
		/// <param name="dlt_buf"></param>
		/// <returns></returns>
		[DllImport("wpcap.dll", EntryPoint = "pcap_list_datalinks", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern Int32 pcap_list_datalinks(Pcap_T p, ref IntPtr dlt_buf);


		/// <summary>
		///Save a capture to file.
		///
		///Note:
		///    : this function does not work in current version of WinPcap.
		///
		///pcap_live_dump() dumps the network traffic from an interface to a file. Using this function the dump is 
		///performed at kernel level, therefore it is more efficient than using pcap_dump().
		///
		///The parameters of this function are an interface descriptor (obtained with pcap_open_live()),
		///a string with the name of the dump file, the maximum size of the file (in bytes) and the maximum 
		///number of packets that the file will contain. Setting maxsize or maxpacks to 0 means no limit. 
		///When maxsize or maxpacks are reached, the dump ends.
		///
		///pcap_live_dump() is non-blocking, threfore Return immediately. pcap_live_dump_ended() can be 
		///used to check the status of the dump process or to wait until it is finished. pcap_close() 
		///can instead be used to end the dump process.
		///
		///Note that when one of the two limits is reached, the dump is stopped, but the file remains opened.
		///In order to correctly flush the data and put the file in a consistent state, the adapter must be 
		///closed with pcap_close().
		///
		///See also:
		///    pcap_live_dump_ended(), pcap_open_live(), pcap_close(), pcap_dump_open(), pcap_dump() 
		/// </summary>
		/// <param name="p"></param>
		/// <param name="filename"></param>
		/// <param name="maxsize"></param>
		/// <param name="maxpacks"></param>
		/// <returns></returns>
		[DllImport("wpcap.dll", EntryPoint = "pcap_live_dump", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern Int32 pcap_live_dump(Pcap_T p, string filename, Int32 maxsize, Int32 maxpacks);



		/// <summary>
		///Return the status of the kernel dump process, i.e. tells if one of the limits defined with pcap_live_dump() has been reached.
		///
		///Note:
		///    : this function does not work in current version of WinPcap.
		///
		///pcap_live_dump_ended() informs the user about the limits that were set with a previous call to pcap_live_dump() on the interface pointed by p: if the return value is nonzero, one of the limits has been reched and the dump process is currently stopped.
		///
		///If sync is nonzero, the function blocks until the dump is finished, otherwise Return immediately.
		///
		///Warning:
		///    if the dump process has no limits (i.e. if the maxsize and maxpacks arguments of pcap_live_dump() were both 0), the dump process will never stop, therefore setting sync to TRUE will block the application on this call forever.
		///
		///See also:
		///    pcap_live_dump() 
		/// </summary>
		/// <param name="p"></param>
		/// <param name="sync"></param>
		/// <returns></returns>
		[DllImport("wpcap.dll", EntryPoint = "pcap_live_dump_ended", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern Int32 pcap_live_dump_ended(Pcap_T p, Int32 sync);


		/// <summary>
		///Return the first valid device in the system.
		///
		///Deprecated:
		///    Use pcap_findalldevs() or pcap_findalldevs_ex() instead.
		///
		///pcap_lookupdev() returns a pointer to a network device suitable for use with pcap_open_live() and pcap_lookupnet(). If there is an error, NULL is returned and errbuf is filled in with an appropriate error message.
		///
		///See also:
		///    pcap_findalldevs(), pcap_open_live() 

		/// </summary>
		/// <param name="errbuf"></param>
		/// <returns></returns>
		[DllImport("wpcap.dll", EntryPoint = "pcap_lookupdev", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern string pcap_lookupdev(StringBuilder errbuf);



		/// <summary>
		///Return the subnet and netmask of an interface.
		///
		///Deprecated:
		///    Use pcap_findalldevs() or pcap_findalldevs_ex() instead.
		///
		///pcap_lookupnet() is used to determine the network number and mask associated with the network device device. Both netp and maskp are bpf_u_int32 pointers. A return of -1 indicates an error in which case errbuf is filled in with an appropriate error message.
		///
		///See also:
		///    pcap_findalldevs() 
		/// </summary>
		/// <param name="?"></param>
		/// <returns></returns>
		[DllImport("wpcap.dll", EntryPoint = "pcap_lookupnet", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern Int32 pcap_lookupnet(string device, BpfUI32Ptr netp, BpfUI32Ptr maskp, StringBuilder errbuf);


		/// <summary>
		/// ///Collect a group of packets.
		///
		///pcap_loop() is similar to pcap_dispatch() except it keeps reading packets until cnt packets are processed or 
		///an error occurs. It does not return when live read timeouts occur. Rather, specifying a non-zero read 
		///timeout to pcap_open_live() and then calling pcap_dispatch() allows the reception and processing of any 
		///packets that arrive when the timeout occurs. A negative cnt causes pcap_loop() to loop forever (or at 
		///least until an error occurs). -1 is returned on an error; 0 is returned if cnt is exhausted; -2 is returned if 
		///the loop terminated due to a call to pcap_breakloop() before any packets were processed. If your application 
		///uses pcap_breakloop(), make sure that you explicitly check for -1 and -2, rather than just checking for a 
		///return value < 0.
		///
		///See also:
		///    pcap_dispatch(), pcap_next(), pcap_open_live(), pcap_open_offline(), pcap_handler 
		/// </summary>
		/// <param name="p"></param>
		/// <param name="cnt"></param>
		/// <param name="callback"></param>
		/// <param name="user"></param>
		/// <returns></returns>
		[DllImport("wpcap.dll", EntryPoint = "pcap_loop", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern Int32 pcap_loop(Pcap_T p, Int32 cnt, PcapHandler callback, string user);


		/// <summary>
		///return the major version number of the pcap library used to write the savefile.
		///
		///See also:
		///    pcap_minor_version() 
		/// </summary>
		/// <param name="p"></param>
		/// <returns></returns>
		[DllImport("wpcap.dll", EntryPoint = "pcap_major_version", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern Int32 pcap_major_version(Pcap_T p);


		/// <summary>
		///return the minor version number of the pcap library used to write the savefile.
		///
		///See also:
		///    pcap_major_version() 
		/// </summary>
		/// <param name="p"></param>
		/// <returns></returns>
		[DllImport("wpcap.dll", EntryPoint = "pcap_minor_version", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern Int32 pcap_minor_version(Pcap_T p);


		/// <summary>
		///Return the next available packet.
		///
		///pcap_next() reads the next packet (by calling pcap_dispatch() with a cnt of 1) and returns a u_char pointer to the data in that packet. (The pcap_pkthdr struct for that packet is not supplied.) NULL is returned if an error occured, or if no packets were read from a live capture (if, for example, they were discarded because they didn't pass the packet filter, or if, on platforms that support a read timeout that starts before any packets arrive, the timeout expires before any packets arrive, or if the file descriptor for the capture device is in non-blocking mode and no packets were available to be read), or if no more packets are available in a ``savefile.'' Unfortunately, there is no way to determine whether an error occured or not.
		///
		///See also:
		///    pcap_dispatch(), pcap_loop() 
		/// </summary>
		/// <param name="p"></param>
		/// <param name="?"></param>
		/// <returns></returns>
		[DllImport("wpcap.dll", EntryPoint = "pcap_next", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern string pcap_next(Pcap_T p, ref PcapPkthdr h);



		/// <summary>
		///Read a packet from an interface or from an offline capture.
		///
		///This function is used to retrieve the next available packet, bypassing the callback method traditionally provided by libpcap.
		///
		///pcap_next_ex fills the pkt_header and pkt_data parameters (see pcap_handler()) with the pointers to the header and to the data of the next captured packet.
		///
		///The return value can be:
		///
		///    * 1 if the packet has been read without problems
		///    * 0 if the timeout set with pcap_open_live() has elapsed. In this case pkt_header and pkt_data don't point to a valid packet
		///    * -1 if an error occurred
		///    * -2 if EOF was reached reading from an offline capture
		///
		///See also:
		///    pcap_open_live(), pcap_loop(), pcap_dispatch(), pcap_handler() 
		/// </summary>
		/// <param name="p"></param>
		/// <param name="?"></param>
		/// <returns></returns>
		[DllImport("wpcap.dll", EntryPoint = "pcap_next_ex", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern Int32 pcap_next_ex(Pcap_T p, ref IntPtr pkt_header, ref IntPtr pkt_data);


		/// <summary>
		/// ///Returns if a given filter applies to an offline packet.
		///
		///This function is used to apply a filter to a packet that is currently in memory. This process does not need to open an adapter; we need just to create the proper filter (by settings parameters like the snapshot length, or the link-layer type) by means of the pcap_compile_nopcap().
		///
		///The current API of libpcap does not allow to receive a packet and to filter the packet after it has been received. However, this can be useful in case you want to filter packets in the application, instead of into the receiving process. This function allows you to do the job.
		///
		///Parameters:
		///    	prog,: 	bpf program (created with the pcap_compile_nopcap() )
		///    	header,: 	header of the packet that has to be filtered
		///    	pkt_data,: 	buffer containing the packet, in network-byte order.
		///
		///Returns:
		///    the length of the bytes that are currently available into the packet if the packet satisfies the filter, 0 otherwise. 
		///
		/// </summary>
		/// <param name="?"></param>
		/// <returns></returns>
		[DllImport("wpcap.dll", EntryPoint = "pcap_offline_filter", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern Boolean pcap_offline_filter(ref BpfProgram prog, ref PcapPkthdr header, string pkt_data);


		/// <summary>
		///Open a generic source in order to capture / send (WinPcap only) traffic.
		///
		///The pcap_open() replaces all the pcap_open_xxx() functions with a single call.
		///
		///This function hides the differences between the different pcap_open_xxx() functions so that the programmer does not have to manage different opening function. In this way, the 'true' open function is decided according to the source type, which is included into the source string (in the form of source prefix).
		///
		///This function can rely on the pcap_createsrcstr() to create the string that keeps the capture device according to the new syntax, and the pcap_parsesrcstr() for the other way round.
		///
		///Parameters:
		///    	source,: 	zero-terminated string containing the source name to open. The source name has to include the format prefix according to the new Source Specification Syntax and it cannot be NULL.
		///    On on Linux systems with 2.2 or later kernels, a device argument of "any" (i.e. rpcap://any) can be used to capture packets from all interfaces.
		///    In order to makes the source syntax easier, please remember that:
		///
		///        * the adapters returned by the pcap_findalldevs_ex() can be used immediately by the pcap_open()
		///        * in case the user wants to pass its own source string to the pcap_open(), the pcap_createsrcstr() helps in creating the correct source identifier.
		///
		///    	snaplen,: 	length of the packet that has to be retained. For each packet received by the filter, only the first 'snaplen' bytes are stored in the buffer and passed to the user application. For instance, snaplen equal to 100 means that only the first 100 bytes of each packet are stored.
		///    	flags,: 	keeps several flags that can be needed for capturing packets. The allowed flags are defined in the pcap_open() flags .
		///    	read_timeout,: 	read timeout in milliseconds. The read timeout is used to arrange that the read not necessarily return immediately when a packet is seen, but that it waits for some amount of time to allow more packets to arrive and to read multiple packets from the OS kernel in one operation. Not all platforms support a read timeout; on platforms that don't, the read timeout is ignored.
		///    	auth,: 	a pointer to a 'struct pcap_rmtauth' that keeps the information required to authenticate the user on a remote machine. In case this is not a remote capture, this pointer can be set to NULL.
		///    	errbuf,: 	a pointer to a user-allocated buffer which will contain the error in case this function fails. The pcap_open() and findalldevs() are the only two functions which have this parameter, since they do not have (yet) a pointer to a pcap_t structure, which reserves space for the error string. Since these functions do not have (yet) a pcap_t pointer (the pcap_t pointer is NULL in case of errors), they need an explicit 'errbuf' variable. 'errbuf' may also be set to warning text when pcap_open_live() succeds; to detect this case the caller should store a zero-length string in 'errbuf' before calling pcap_open_live() and display the warning to the user if 'errbuf' is no longer a zero-length string.
		///
		///Returns:
		///    A pointer to a 'pcap_t' which can be used as a parameter to the following calls (pcap_compile() and so on) and that specifies an opened WinPcap session. In case of problems, it returns NULL and the 'errbuf' variable keeps the error message.
		///
		///Warning:
		///    The source cannot be larger than PCAP_BUF_SIZE.
		///
		///    The following formats are not allowed as 'source' strings:
		///
		///        * rpcap:// [to open the first local adapter]
		///        * rpcap://hostname/ [to open the first remote adapter] 
		/// </summary>
		/// <param name="?"></param>
		/// <returns></returns>
		[DllImport("wpcap.dll", EntryPoint = "pcap_open", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern Pcap_T pcap_open(string source, Int32 snaplen, Int32 flags, Int32 read_timeout, ref PcapRmtAuth auth, StringBuilder errbuf);


		/// <summary>
		/// Create a pcap_t structure without starting a capture.
		///
		///pcap_open_dead() is used for creating a pcap_t structure to use when calling the other functions in libpcap. It is typically used when just using libpcap for compiling BPF code.
		///
		///See also:
		///    pcap_open_offline(), pcap_open_live(), pcap_findalldevs(), pcap_compile(), pcap_setfilter(), pcap_close() 
		/// </summary>
		/// <param name="linktype"></param>
		/// <param name="snaplen"></param>
		/// <returns></returns>
		[DllImport("wpcap.dll", EntryPoint = "pcap_open_dead", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern Pcap_T pcap_open_dead(Int32 linktype, Int32 snaplen);


		/// <summary>
		///Open a live capture from the network.
		///
		///pcap_open_live() is used to obtain a packet capture descriptor to look at packets on the network. device is a string that specifies the network device to open; on Linux systems with 2.2 or later kernels, a device argument of "any" or NULL can be used to capture packets from all interfaces. snaplen specifies the maximum number of bytes to capture. If this value is less than the size of a packet that is captured, only the first snaplen bytes of that packet will be captured and provided as packet data. A value of 65535 should be sufficient, on most if not all networks, to capture all the data available from the packet. promisc specifies if the interface is to be put into promiscuous mode. (Note that even if this parameter is false, the interface could well be in promiscuous mode for some other reason.) For now, this doesn't work on the "any" device; if an argument of "any" or NULL is supplied, the promisc flag is ignored. to_ms specifies the read timeout in milliseconds. The read timeout is used to arrange that the read not necessarily return immediately when a packet is seen, but that it wait for some amount of time to allow more packets to arrive and to read multiple packets from the OS kernel in one operation. Not all platforms support a read timeout; on platforms that don't, the read timeout is ignored. A zero value for to_ms, on platforms that support a read timeout, will cause a read to wait forever to allow enough packets to arrive, with no timeout. errbuf is used to return error or warning text. It will be set to error text when pcap_open_live() fails and returns NULL. errbuf may also be set to warning text when pcap_open_live() succeds; to detect this case the caller should store a zero-length string in errbuf before calling pcap_open_live() and display the warning to the user if errbuf is no longer a zero-length string.
		///
		///See also:
		///    pcap_open_offline(), pcap_open_dead(), pcap_findalldevs(), pcap_close() 
		/// </summary>
		/// <param name="?"></param>
		/// <returns></returns>
		[DllImport("wpcap.dll", EntryPoint = "pcap_open_live", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern Pcap_T pcap_open_live(string device, Int32 snaplen, Int32 promisc, Int32 to_ms, StringBuilder ebuf); 


		/// <summary>
		/// Open a savefile in the tcpdump/libpcap format to read packets.
		/// 
		/// pcap_open_offline() is called to open a "savefile" for reading. fname specifies the name of the file to open. The file has the same format as those used by tcpdump(1) and tcpslice(1). The name "-" in a synonym for stdin. Alternatively, you may call pcap_fopen_offline() to read dumped data from an existing open stream fp. Note that on Windows, that stream should be opened in binary mode. errbuf is used to return error text and is only set when pcap_open_offline() or pcap_fopen_offline() fails and returns NULL.
		///
		///See also:   pcap_open_live(), pcap_dump_open(), pcap_findalldevs(), pcap_close() 
		/// </summary>
		/// <param name="?"></param>
		/// <returns></returns>
		[DllImport("wpcap.dll", EntryPoint = "pcap_open_offline", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern Pcap_T pcap_open_offline(string fname, StringBuilder errbuf);



		/// <summary>
		///Parse the source string and returns the pieces in which the source can be split.
		///
		///This call is the other way round of pcap_createsrcstr(). It accepts a null-terminated string and it returns the parameters related to the source. This includes:
		///
		///    * the type of the source (file, winpcap on a remote adapter, winpcap on local adapter), which is determined by the source prefix (PCAP_SRC_IF_STRING and so on)
		///    * the host on which the capture has to be started (only for remote captures)
		///    * the 'raw' name of the source (file name, name of the remote adapter, name of the local adapter), without the source prefix. The string returned does not include the type of the source itself (i.e. the string returned does not include "file://" or rpcap:// or such).
		///
		///The user can omit some parameters in case it is not interested in them.
		///
		///Parameters:
		///    	source,: 	a null-terminated string containing the WinPcap source. This source starts with an identifier according to the new Source Specification Syntax .
		///    	type,: 	pointer to an integer, which is used to return the code corrisponding to the selected source. The code will be one defined in the Source identification Codes .
		///    In case the source string does not exists (i.e. 'source == NULL') or it is empty ('*source == NULL'), it returns PCAP_SRC_IF_LOCAL (i.e. you are ready to call pcap_open_live() ). This behavior is kept only for compatibility with older applications (e.g. tcpdump); therefore we suggest to move to the new syntax for sources.
		///    This parameter can be NULL in case the user is not interested in that.
		///    	host,: 	user-allocated buffer (of size PCAP_BUF_SIZE) that is used to return the host name on which the capture has to be started. This value is meaningful only in case of remote capture; otherwise, the returned string will be empty (""). This parameter can be NULL in case the user is not interested in that.
		///    	port,: 	user-allocated buffer (of size PCAP_BUF_SIZE) that is used to return the port that has to be used by the RPCAP protocol to contact the other host. This value is meaningful only in case of remote capture and if the user wants to use a non-standard port; otherwise, the returned string will be empty (""). In case of remote capture, an emply string means "use the standard RPCAP port". This parameter can be NULL in case the user is not interested in that.
		///    	name,: 	user-allocated buffer (of size PCAP_BUF_SIZE) that is used to return the source name, without the source prefix. If the name does not exist (for example because source contains 'rpcap://' that means 'default local adapter'), it returns NULL. This parameter can be NULL in case the user is not interested in that.
		///    	errbuf,: 	pointer to a user-allocated buffer (of size PCAP_ERRBUF_SIZE) that will contain the error message (in case there is one). This parameter can be NULL in case the user is not interested in that.
		///
		///Returns:
		///    '0' if everything is fine, '-1' if some errors occurred. The requested values (host name, network port, type of the source) are returned into the proper variables passed by reference. 
		///
		/// </summary>
		/// <param name="?"></param>
		/// <returns></returns>

		[DllImport("wpcap.dll", EntryPoint = "pcap_parsesrcstr", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern Int32 pcap_parsesrcstr(string source, ref Int32 type, StringBuilder host, StringBuilder port, StringBuilder name, StringBuilder errbuf);



		/// <summary>
		///print the text of the last pcap library error on stderr, prefixed by prefix.
		///
		///See also:
		///    pcap_geterr() 
		/// </summary>
		/// <param name="p"></param>
		/// <param name="prefix"></param>
		[DllImport("wpcap.dll", EntryPoint = "pcap_perror", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern void pcap_perror(Pcap_T p, string prefix);


		/// <summary>
		///Block until a network connection is accepted (active mode only).
		///
		///This function has been defined to allow the client dealing with the 'active mode'. In other words, in the 'active mode' the server opens the connection toward the client, so that the client has to open a socket in order to wait for connections. When a new connection is accepted, the RPCAP protocol starts as usual; the only difference is that the connection is initiated by the server.
		///
		///This function accepts only ONE connection, then it closes the waiting socket. This means that if some error occurs, the application has to call it again in order to accept another connection.
		///
		///This function returns when a new connection (coming from a valid host 'connectinghost') is accepted; it returns error otherwise.
		///
		///Parameters:
		///    	address,: 	a string that keeps the network address we have to bind to; usually it is NULL (it means 'bind on all local addresses').
		///    	port,: 	a string that keeps the network port on which we have to bind to; usually it is NULL (it means 'bind on the predefined port', i.e. RPCAP_DEFAULT_NETPORT_ACTIVE).
		///    	hostlist,: 	a string that keeps the host name of the host from whom we are expecting a connection; it can be NULL (it means 'accept connection from everyone'). Host names are separated by a whatever character in the RPCAP_HOSTLIST_SEP list.
		///    	connectinghost,: 	a user-allocated buffer that will contain the name of the host is trying to connect to us. This variable must be at least RPCAP_HOSTLIST_SIZE bytes..
		///    	auth,: 	a pointer to a pcap_rmtauth structure. This pointer keeps the information required to authenticate the RPCAP connection to the remote host.
		///    	errbuf,: 	a pointer to a user-allocated buffer (of size PCAP_ERRBUF_SIZE) that will contain the error message (in case there is one).
		///
		///Returns:
		///    The SOCKET identifier of the new control connection if everything is fine, a negative number if some errors occurred. The error message is returned into the errbuf variable. In case it returns '-1', this means 'everything is fine', but the host cannot be admitted. In case it returns '-2', in means 'unrecoverable error' (for example it is not able to bind the socket, or something like that). In case it returns '-3', it means 'authentication failed'. The authentication check is performed only if the connecting host is among the ones that are allowed to connect to this host.
		///
		///The host that is connecting to us is returned into the hostlist variable, which ust be allocated by the user. This variable contains the host name both in case the host is allowed, and in case the connection is refused.
		///
		///Warning:
		///    Although this function returns the socket established by the new control connection, this value should not be used. This value will be stored into some libpcap internal variables and it will be managed automatically by the library. In other words, all the following calls to findalldevs() and pcap_open() will check if the host is among one that already has a control connection in place; if so, that one will be used.
		///
		///    This function has several problems if used inside a thread, which is stopped when this call is blocked into the accept(). In this case, the socket on which we accept connections is not freed (thread termination is a very dirty job), so that we are no longer able to accept other connections until the program (i.e. the process) stops. In order to solve the problem, call the pcap_remoteact_cleanup(). 
		/// </summary>
		/// <param name="?"></param>
		/// <returns></returns>
		[DllImport("wpcap.dll", EntryPoint = "pcap_remoteact_accept", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern IntPtr pcap_remoteact_accept(string address, string port, string hostlist, StringBuilder connectinghost, ref PcapRmtAuth auth, StringBuilder errbuf);

		/// <summary>
		/// ///Clean the socket that is currently used in waiting active connections.
		///
		///This function does a very dirty job. The fact is that is the waiting socket is not freed if the pcap_remoteaccept() is killed inside a new thread. This function is able to clean the socket in order to allow the next calls to pcap_remoteact_accept() to work.
		///
		///This function is useful *only* if you launch pcap_remoteact_accept() inside a new thread, and you stops (not very gracefully) the thread (for example because the user changed idea, and it does no longer want to wait for an active connection). So, basically, the flow should be the following:
		///
		///    * launch a new thread
		///    * call the pcap_remoteact_accept
		///    * if this new thread is killed, call pcap_remoteact_cleanup().
		///
		///This function has no effects in other cases.
		///
		///Returns:
		///    None. 
		/// </summary>

		[DllImport("wpcap.dll", EntryPoint = "pcap_remoteact_cleanup", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern void pcap_remoteact_cleanup();


		/// <summary>
		/// ///Drop an active connection (active mode only).
		///
		///This function has been defined to allow the client dealing with the 'active mode'. This function closes an active connection that is still in place and it purges the host name from the 'activeHost' list. From this point on, the client will not have any connection with that host in place.
		///
		///Parameters:
		///    	host,: 	a string that keeps the host name of the host for which we want to close the active connection.
		///    	errbuf,: 	a pointer to a user-allocated buffer (of size PCAP_ERRBUF_SIZE) that will contain the error message (in case there is one).
		///
		///Returns:
		///    '0' if everything is fine, '-1' if some errors occurred. The error message is returned into the errbuf variable. 
		/// </summary>
		/// <param name="?"></param>
		/// <returns></returns>
		[DllImport("wpcap.dll", EntryPoint = "pcap_remoteact_close", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern Int32 pcap_remoteact_close(string host, StringBuilder errbuf);


		/// <summary>
		///Return the hostname of the host that have an active connection with us (active mode only).
		///
		///This function has been defined to allow the client dealing with the 'active mode'. This function returns the list of hosts that are currently having an active connection with us. This function is useful in order to delete an active connection that is still in place.
		///
		///Parameters:
		///    	hostlist,: 	a user-allocated string that will keep the list of host that are currently connected with us.
		///    	sep,: 	the character that has to be sued as a separator between the hosts (',' for example).
		///    	size,: 	size of the hostlist buffer.
		///    	errbuf,: 	a pointer to a user-allocated buffer (of size PCAP_ERRBUF_SIZE) that will contain the error message (in case there is one).
		///
		///Returns:
		///    '0' if everything is fine, '-1' if some errors occurred. The error message is returned into the errbuf variable. 
		/// </summary>
		/// <param name="hostlist"></param>
		/// <param name="sep"></param>
		/// <param name="size"></param>
		/// <param name="errbuf"></param>
		/// <returns></returns>
		[DllImport("wpcap.dll", EntryPoint = "pcap_remoteact_list", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern Int32 pcap_remoteact_list(StringBuilder hostlist, ref char sep, Int32 size, StringBuilder errbuf);


		/// <summary>
		///	Send a raw packet.
		///
		///This function allows to send a raw packet to the network. p is the interface that will be used to send the 
		///packet, buf contains the data of the packet to send (including the various protocol headers), size is the 
		///dimension of the buffer pointed by buf, i.e. the size of the packet to send. The MAC CRC doesn't need to
		///be included, because it is transparently calculated and added by the network interface driver. The return 
		///value is 0 if the packet is succesfully sent, -1 otherwise.
		///
		///See also:
		///    pcap_open_live() 
		///
		///pcap_send_queue* pcap_sendqueue_alloc 	( 	u_int  	memsize 	 )  	
		///
		///Allocate a send queue.
		///
		///This function allocates a send queue, i.e. a buffer containing a set of raw packets that will be transimtted on the network with pcap_sendqueue_transmit().
		///
		///memsize is the size, in bytes, of the queue, therefore it determines the maximum amount of data that the queue will contain.
		///
		///Use pcap_sendqueue_queue() to insert packets in the queue.
		///
		///See also:
		///    pcap_sendqueue_queue(), pcap_sendqueue_transmit(), pcap_sendqueue_destroy() 
		/// </summary>
		/// <param name="p"></param>
		/// <param name="buf"></param>
		/// <param name="size"></param>
		/// <returns></returns>
		[DllImport("wpcap.dll", EntryPoint = "pcap_sendpacket", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern Int32 pcap_sendpacket(Pcap_T p, string buf, Int32 size10);

		/// <summary>
		///
		///Destroy a send queue.
		///
		///Deletes a send queue and frees all the memory associated with it.
		///
		///See also:
		///    pcap_sendqueue_alloc(), pcap_sendqueue_queue(), pcap_sendqueue_transmit() 
		/// </summary>
		/// <param name="queue"></param>
		[DllImport("wpcap.dll", EntryPoint = "pcap_sendqueue_destroy", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern void pcap_sendqueue_destroy(ref PcapSendQueue queue);


		/// <summary>
		///Add a packet to a send queue.
		///
		///pcap_sendqueue_queue() adds a packet at the end of the send queue pointed by the queue parameter. 
		///pkt_header points to a pcap_pkthdr structure with the timestamp and the length of the packet,
		///pkt_data points to a buffer with the data of the packet.
		///
		///The pcap_pkthdr structure is the same used by WinPcap and libpcap to store the packets in a file, therefore sending a capture file is straightforward. 'Raw packet' means that the sending application will have to include the protocol headers, since every packet is sent to the network 'as is'. The CRC of the packets needs not to be calculated, because it will be transparently added by the network interface.
		///
		///See also:
		///    pcap_sendqueue_alloc(), pcap_sendqueue_transmit(), pcap_sendqueue_destroy() 
		/// </summary>
		/// <param name="queue"></param>
		/// <param name="?"></param>
		/// <returns></returns>
		[DllImport("wpcap.dll", EntryPoint = "pcap_sendqueue_queue", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern Int32 pcap_sendqueue_queue(ref PcapSendQueue queue, ref PcapPkthdr pkt_header, string pkt_data);


		/// <summary>
		///Send a queue of raw packets to the network.
		///
		///This function transmits the content of a queue to the wire. p is a pointer to the adapter on which the packets will be sent, queue points to a pcap_send_queue structure containing the packets to send (see pcap_sendqueue_alloc() and pcap_sendqueue_queue()), sync determines if the send operation must be synchronized: if it is non-zero, the packets are sent respecting the timestamps, otherwise they are sent as fast as possible.
		///
		///The return value is the amount of bytes actually sent. If it is smaller than the size parameter, an error occurred during the send. The error can be caused by a driver/adapter problem or by an inconsistent/bogus send queue.
		///
		///Note:
		///    Using this function is more efficient than issuing a series of pcap_sendpacket(), because the packets are buffered in the kernel driver, so the number of context switches is reduced. Therefore, expect a better throughput when using pcap_sendqueue_transmit.
		///
		///    When Sync is set to TRUE, the packets are synchronized in the kernel with a high precision timestamp. This requires a non-negligible amount of CPU, but allows normally to send the packets with a precision of some microseconds (depending on the accuracy of the performance counter of the machine). Such a precision cannot be reached sending the packets with pcap_sendpacket().
		///
		///See also:
		///    pcap_sendqueue_alloc(), pcap_sendqueue_queue(), pcap_sendqueue_destroy() 
		/// </summary>
		/// <param name="p"></param>
		/// <param name="queue"></param>
		/// <param name="sync"></param>
		/// <returns></returns>
		[DllImport("wpcap.dll", EntryPoint = "pcap_sendqueue_transmit", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern UInt32 pcap_sendqueue_transmit(Pcap_T p, ref PcapSendQueue queue, Int32 sync);


		/// <summary>
		/// Set the current data link type of the pcap descriptor to the type specified by dlt. -1 is returned on failure.
		/// </summary>
		/// <param name="p"></param>
		/// <param name="dlt"></param>
		/// <returns></returns>
		[DllImport("wpcap.dll", EntryPoint = "pcap_set_datalink", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern int pcap_set_datalink(Pcap_T p, Int32 dlt);


		/// <summary>
		///Set the size of the kernel buffer associated with an adapter.
		///
		///dim specifies the size of the buffer in bytes. The return value is 0 when the call succeeds, -1 otherwise. If an old buffer was already created with a previous call to pcap_setbuff(), it is deleted and its content is discarded. pcap_open_live() creates a 1 MByte buffer by default.
		///
		///See also:
		///    pcap_open_live(), pcap_loop(), pcap_dispatch() 
		/// </summary>
		/// <param name="p"></param>
		/// <param name="dim"></param>
		/// <returns></returns>
		[DllImport("wpcap.dll", EntryPoint = "pcap_setbuff", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern Int32 pcap_setbuff(Pcap_T p, Int32 dim);

		///Associate a filter to a capture.
		///
		///pcap_setfilter() is used to specify a filter program. fp is a pointer to a bpf_program struct, usually the result of a call to pcap_compile(). -1 is returned on failure, in which case pcap_geterr() may be used to display the error text; 0 is returned on success.
		///
		///See also:
		///    pcap_compile(), pcap_compile_nopcap() 
		[DllImport("wpcap.dll", EntryPoint = "pcap_setfilter", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern Int32 pcap_setfilter(Pcap_T p, ref BpfProgram fp);

		///Set the minumum amount of data received by the kernel in a single call.
		///
		///pcap_setmintocopy() changes the minimum amount of data in the kernel buffer that causes a read from the application to return (unless the timeout expires). If the value of size is large, the kernel is forced to wait the arrival of several packets before copying the data to the user. This guarantees a low number of system calls, i.e. low processor usage, and is a good setting for applications like packet-sniffers and protocol analyzers. Vice versa, in presence of a small value for this variable, the kernel will copy the packets as soon as the application is ready to receive them. This is useful for real time applications that need the best responsiveness from the kernel.
		///
		///See also:
		///    pcap_open_live(), pcap_loop(), pcap_dispatch() 
		[DllImport("wpcap.dll", EntryPoint = "pcap_setmintocopy", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern Int32 pcap_setmintocopy(Pcap_T p, Int32 size);


		///Set the working mode of the interface p to mode.
		///
		///Valid values for mode are MODE_CAPT (default capture mode) and MODE_STAT (statistical mode). See the tutorial "\ref wpcap_tut9" for details about statistical mode.
		[DllImport("wpcap.dll", EntryPoint = "pcap_setmode", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern Int32 pcap_setmode(Pcap_T p, Int32 mode);

		///Switch between blocking and nonblocking mode.
		///
		///pcap_setnonblock() puts a capture descriptor, opened with pcap_open_live(), into "non-blocking" mode, or takes it out of "non-blocking" mode, depending on whether the nonblock argument is non-zero or zero. It has no effect on "savefiles". If there is an error, -1 is returned and errbuf is filled in with an appropriate error message; otherwise, 0 is returned. In "non-blocking" mode, an attempt to read from the capture descriptor with pcap_dispatch() will, if no packets are currently available to be read, return 0 immediately rather than blocking waiting for packets to arrive. pcap_loop() and pcap_next() will not work in "non-blocking" mode.
		///
		///See also:
		///    pcap_getnonblock(), pcap_dispatch() 
		[DllImport("wpcap.dll", EntryPoint = "pcap_setnonblock", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern Int32 pcap_setnonblock(Pcap_T p, Int32 nonblock, StringBuilder errbuf);

		///Define a sampling method for packet capture.
		///
		///This function allows applying a sampling method to the packet capture process. The currently sampling methods (and the way to set them) are described into the struct pcap_samp. In other words, the user must set the appropriate parameters into it; these will be applied as soon as the capture starts.
		///
		///Warning:
		///    Sampling parameters cannot be changed when a capture is active. These parameters must be applied before starting the capture. If they are applied when the capture is in progress, the new settings are ignored.
		///
		///    Sampling works only when capturing data on Win32 or reading from a file. It has not been implemented on other platforms. Sampling works on remote machines provided that the probe (i.e. the capturing device) is a Win32 workstation. 
		///
		[DllImport("wpcap.dll", EntryPoint = "pcap_setsampling", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern PcapSamp pcap_setsampling(Pcap_T p);


		///Return the dimension of the packet portion (in bytes) that is delivered to the application.
		///
		///pcap_snapshot() returns the snapshot length specified when pcap_open_live was called.
		///
		///See also:
		///    pcap_open_live(), pcap_compile(), pcap_compile_nopcap() 
		[DllImport("wpcap.dll", EntryPoint = "pcap_snapshot", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern Int32 pcap_snapshot(Pcap_T p);

		///Return statistics on current capture.
		///
		///pcap_stats() returns 0 and fills in a pcap_stat struct. The values represent packet statistics from the start of the run to the time of the call. If there is an error or the underlying packet capture doesn't support packet statistics, -1 is returned and the error text can be obtained with pcap_perror() or pcap_geterr(). pcap_stats() is supported only on live captures, not on "savefiles"; no statistics are stored in "savefiles", so no statistics are available when reading from a "savefile".
		///
		///See also:
		///    pcap_stats_ex(), pcap_open_live() 
		[DllImport("wpcap.dll", EntryPoint = "pcap_stats", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern Int32 pcap_stats(Pcap_T p, ref PcapStat ps);

		///
		///pcap_stats_ex() extends the pcap_stats() allowing to return more statistical parameters than the old call. One of the advantages of this new call is that the pcap_stat structure is not allocated by the user; instead, it is returned back by the system. This allow to extend the pcap_stat structure without affecting backward compatibility on older applications. These will simply check at the values of the members at the beginning of the structure, while only newest applications are able to read new statistical values, which are appended in tail.
		///
		///To be sure not to read a piece of mamory which has not been allocated by the system, the variable pcap_stat_size will return back the size of the structure pcap_stat allocated by the system.
		///
		///Parameters:
		///    	p,: 	pointer to the pcap_t currently in use.
		///    	pcap_stat_size,: 	pointer to an integer that will contain (when the function returns back) the size of the structure pcap_stat as it has been allocated by the system.
		///
		///Returns:
		///    : a pointer to a pcap_stat structure, that will contain the statistics related to the current device. The return value is NULL in case of errors, and the error text can be obtained with pcap_perror() or pcap_geterr().
		///
		///Warning:
		///    pcap_stats_ex() is supported only on live captures, not on "savefiles"; no statistics are stored in "savefiles", so no statistics are available when reading from a "savefile".
		///
		///See also:
		///    pcap_stats() 
		[DllImport("wpcap.dll", EntryPoint = "pcap_stats_ex", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern PcapStat pcap_stats_ex(Pcap_T p, ref Int32 pcap_stat_size);


		///Provided in case strerror() isn't available.
		///
		///See also:
		///    pcap_perror(), pcap_geterr() 
		///
		[DllImport("wpcap.dll", EntryPoint = "pcap_strerror", CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		public static extern string pcap_strerror(Int32 error);

		
	}
}
