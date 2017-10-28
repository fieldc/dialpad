using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Remoting.Messaging;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Effects;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Windows.Threading;
using System.Reflection;
using System.Xml.Serialization;
using WinForms = System.Windows.Forms;


namespace WpfSearcher
{
	/// <summary>
	/// Interaction logic for App.xaml
	/// </summary>
	public partial class App : Application
	{
		private UserSearcher searcher;
		private Settings settings;
		private DialPad dialpad;
		private DataStore configSettings;
		/// <summary>
		/// 
		/// </summary>
		private ManagedWinapi.Hotkey searchHotkey;
		private ManagedWinapi.Hotkey dialHotkey;
		private ManagedWinapi.Hotkey intlHotkey;

		/// <summary>
		/// 
		/// </summary>
		private WinForms.NotifyIcon sysTrayIcon;
		/// <summary>
		/// 
		/// </summary>
		private WinForms.ContextMenuStrip cmsSysTray;
		/// <summary>
		/// 
		/// </summary>
		private CDPListener listener;

		/// <summary>
		/// 
		/// </summary>
		private PhoneAlert alerter;
		/// <summary>
		/// 
		/// </summary>
		private DispatcherTimer noPhonesAlert;
		/// <summary>
		/// 
		/// </summary>
		public delegate void SimpleDelegate();

		private void WPFSearcher_Startup(object sender, StartupEventArgs e)
		{
			Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": Starting up");

			//Veirfy we are not runnign;
			if (System.Diagnostics.Process.GetProcessesByName(System.Diagnostics.Process.GetCurrentProcess().ProcessName).Length > 1)
			{
				Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": I am already running");
				Application.Current.Shutdown();
				return;
			}

			this.configSettings = DataStore.Instance;

			//start CDP listener 
			listener = new CDPListener(configSettings.DiscoverPhones);
			listener.PhonesFound += new EventHandler(listener_PhonesFound);
			this.noPhonesAlert = new DispatcherTimer();
			this.noPhonesAlert.Interval = TimeSpan.FromSeconds(90);
			this.noPhonesAlert.Tick += new EventHandler(noPhonesAlert_Tick);
			if (configSettings.DiscoverPhones)
				this.noPhonesAlert.Start();

			if (!string.IsNullOrEmpty(configSettings.IpAddress))
				listener.AddPhoneManually(configSettings.IpAddress);

			//setup systray icon
			sysTrayIcon = new WinForms.NotifyIcon();
			sysTrayIcon.Icon = WpfSearcher.Properties.Resources.SearchIcon;

			//Context Menu Items
			WinForms.ToolStripMenuItem exitItem = new WinForms.ToolStripMenuItem("&Exit");
			exitItem.Click += new EventHandler(exitItem_Click);
			WinForms.ToolStripMenuItem settingsItem = new WinForms.ToolStripMenuItem("&Settings");
			settingsItem.Click += new EventHandler(settingsItem_Click);
			WinForms.ToolStripMenuItem showItem = new WinForms.ToolStripMenuItem("&Search");
			showItem.Click += new EventHandler(showItem_Click);
			WinForms.ToolStripMenuItem dialItem = new WinForms.ToolStripMenuItem("&Dial Pad");
			dialItem.Click += new EventHandler(dialItem_Click);
			dialItem.Name = "dialItem";
			dialItem.Enabled = false;
			WinForms.ToolStripMenuItem dialerItem = new WinForms.ToolStripMenuItem("&Dialer");
			dialerItem.Click += new EventHandler(dialer_Click);
			dialerItem.Enabled = false;
			dialerItem.Name = "dialerItem";

			cmsSysTray = new WinForms.ContextMenuStrip();
			cmsSysTray.ShowCheckMargin = false;
			cmsSysTray.ShowImageMargin = false;
			cmsSysTray.Margin = new WinForms.Padding(10, 2, 2, 2);
			cmsSysTray.Items.Add(showItem);
			cmsSysTray.Items.Add(dialerItem);
			cmsSysTray.Items.Add(dialItem);
			cmsSysTray.Items.Add(settingsItem);
			cmsSysTray.Items.Add(exitItem);
			sysTrayIcon.ContextMenuStrip = cmsSysTray;
			sysTrayIcon.MouseDoubleClick += new System.Windows.Forms.MouseEventHandler(sysTrayIcon_MouseDoubleClick);
			

			searchHotkey = new ManagedWinapi.Hotkey();
			searchHotkey.WindowsKey = true;
            searchHotkey.Shift = true;
			searchHotkey.KeyCode = System.Windows.Forms.Keys.S;
			searchHotkey.HotkeyPressed += new EventHandler(searchHotkey_HotkeyPressed);
			try
			{
				searchHotkey.Enabled = true;
			}
			catch (ManagedWinapi.HotkeyAlreadyInUseException)
			{
				System.Windows.MessageBox.Show("Could not register searchHotkey (already in use).", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
			}

			dialHotkey = new ManagedWinapi.Hotkey();
			dialHotkey.WindowsKey = true;
            searchHotkey.Shift = true;
			dialHotkey.KeyCode = System.Windows.Forms.Keys.C;
			dialHotkey.HotkeyPressed += new EventHandler(dialHotkey_HotkeyPressed);
			try
			{
				dialHotkey.Enabled = true;
			}
			catch (ManagedWinapi.HotkeyAlreadyInUseException)
			{
				System.Windows.MessageBox.Show("Could not register dialHotkey (already in use).", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
			}
			
			intlHotkey = new ManagedWinapi.Hotkey();
			intlHotkey.WindowsKey = true;
            searchHotkey.Shift = true;
			intlHotkey.KeyCode = System.Windows.Forms.Keys.I;
			intlHotkey.HotkeyPressed += new EventHandler(intlHotkey_HotkeyPressed);
			try
			{
				intlHotkey.Enabled = true;
			}
			catch (ManagedWinapi.HotkeyAlreadyInUseException)
			{
				System.Windows.MessageBox.Show("Could not register intlHotkey (already in use).", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
			}
			sysTrayIcon.Visible = true;

			alerter = new PhoneAlert();
			alerter.Show();

			//initialize now to speed up app
			new UserSearcher(SearcherModes.SEARCH);
			new DialPad();
			new Settings();

		}

		void EnableDialing()
		{
			this.Dispatcher.BeginInvoke(DispatcherPriority.Input, new SimpleDelegate(delegate { this.alerter.NotifyContent.Clear(); this.alerter.NotifyContent.Add(new NotifyObject("IP Phone found, dialing and extra functionality now enabled", "Phone found")); this.alerter.Notify(); }));
			this.Dispatcher.BeginInvoke(DispatcherPriority.Input, new SimpleDelegate(delegate { cmsSysTray.Items["dialItem"].Enabled = true; }));
			this.Dispatcher.BeginInvoke(DispatcherPriority.Input, new SimpleDelegate(delegate { cmsSysTray.Items["dialerItem"].Enabled = true; }));
		}

		void DisableDialing()
		{

			this.Dispatcher.BeginInvoke(DispatcherPriority.Input, new SimpleDelegate(delegate { this.alerter.NotifyContent.Clear(); this.alerter.NotifyContent.Add(new NotifyObject("No IP Phones found, dialing will be disabled", "No Phones found")); this.alerter.Notify(); }));
			this.Dispatcher.BeginInvoke(DispatcherPriority.Input, new SimpleDelegate(delegate { cmsSysTray.Items["dialItem"].Enabled = false; }));
			this.Dispatcher.BeginInvoke(DispatcherPriority.Input, new SimpleDelegate(delegate { cmsSysTray.Items["dialerItem"].Enabled = false; }));
		}

		private void ShowSearcher(SearcherModes mode)
		{
			if (this.searcher != null)
			{
				this.searcher.Close();
			}
			this.searcher = new UserSearcher(mode);
			searcher.Show();
		}

		private void WPFSearcher_Exit(object sender, ExitEventArgs e)
		{
			Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": Exiting Appliation");
			if (this.searcher != null)
				this.searcher.Close();

			if (this.dialpad != null)
				this.dialpad.Close();

			if (this.settings != null)
				this.settings.Close();

			if (this.sysTrayIcon != null)
			{
				Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": Hiding Systray");
				this.sysTrayIcon.Visible = false;
			}
			if (searchHotkey != null)
			{
				Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": Ditching hotkeys");
				searchHotkey.Dispose();
			}
			if (this.listener != null)
			{
				Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": Stoping listener");
				this.listener.ShutDown = true;
			}

			///Save Config
			try
			{
				DataStore.Instance.Save();
			}
			catch (Exception ex)
			{
				Debug.WriteLine(ex.Message);
			}
			
		}

		void settingsItem_Click(object sender, EventArgs e)
		{
			if (this.settings != null)
				this.settings.Close();

			this.settings = new Settings();
			this.settings.Show();
			this.settings.Closed += new EventHandler(settings_Closed);
		}

		void settings_Closed(object sender, EventArgs e)
		{
			Debug.WriteLine("Engaging settings");
			this.listener.RunAutoDiscovery(DataStore.Instance.DiscoverPhones);
			if (!string.IsNullOrEmpty(DataStore.Instance.IpAddress))
			{
				this.listener.AddPhoneManually(DataStore.Instance.IpAddress);
			}
			else
			{
				bool hadPhones = CDPListener.HaveAttachedPhones;
				this.listener.RemoveManuallyAddedPhone();
				if (hadPhones && !CDPListener.HaveAttachedPhones)
				{
					this.DisableDialing();
				}
				else if (!hadPhones && CDPListener.HaveAttachedPhones) 
				{
					this.EnableDialing();
				}
			}

		}

		void dialer_Click(object sender, EventArgs e)
		{
			if (CDPListener.HaveAttachedPhones)
			{
				this.ShowSearcher(SearcherModes.DIAL);
			}
		}

		void dialItem_Click(object sender, EventArgs e)
		{
			
			if (this.dialpad != null)
				this.dialpad.Close();

			this.dialpad = new DialPad();
			this.dialpad.Show();
		}


		/// <summary>
		/// 
		/// </summary>
		/// <param name="sender"></param>
		/// <param name="e"></param>
		private void showItem_Click(object sender, EventArgs e)
		{
			this.ShowSearcher(SearcherModes.SEARCH);
		}


		/// <summary>
		/// 
		/// </summary>
		/// <param name="sender"></param>
		/// <param name="e"></param>
		private void exitItem_Click(object sender, EventArgs e)
		{
			if (this.searcher != null)
			{
				this.searcher.Close();
				this.searcher = null;
			}
			Application.Current.Shutdown();
		}

		void noPhonesAlert_Tick(object sender, EventArgs e)
		{
			if (!CDPListener.HaveAttachedPhones)
			{
				this.Dispatcher.BeginInvoke(DispatcherPriority.Input, new SimpleDelegate(delegate { this.alerter.NotifyContent.Clear(); this.alerter.NotifyContent.Add(new NotifyObject("No IP Phones found, dialing will be disabled", "No Phones found")); this.alerter.Notify(); }));
			}
			this.noPhonesAlert.Stop();
		}

		void listener_PhonesFound(object sender, EventArgs e)
		{
			Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": Found Phone");
			this.EnableDialing();
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="sender"></param>
		/// <param name="e"></param>
		private void sysTrayIcon_MouseDoubleClick(object sender, System.Windows.Forms.MouseEventArgs e)
		{
			this.ShowSearcher(SearcherModes.SEARCH);
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="sender"></param>
		/// <param name="e"></param>
		private void searchHotkey_HotkeyPressed(object sender, EventArgs e)
		{
			this.ShowSearcher(SearcherModes.SEARCH);
		}

		void intlHotkey_HotkeyPressed(object sender, EventArgs e)
		{
			this.ShowSearcher(SearcherModes.INTLSEARCH);
		}

		void dialHotkey_HotkeyPressed(object sender, EventArgs e)
		{
			if (CDPListener.HaveAttachedPhones)
			{
				this.ShowSearcher(SearcherModes.DIAL);
			}
		}

	}
}
