using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Reflection;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media.Imaging;
using System.Windows.Media.Animation;
using dotnet3Threading = System.Windows.Threading;
using CiscoPhone;
using dotnet2 = System.Drawing;

namespace WpfSearcher
{
	/// <summary>
	/// Interaction logic for DialPad.xaml
	/// </summary>
	public partial class DialPad : Window
	{
		private object phoneLock;
		private bool showAsterisk;
		private delegate void ScreenDelegate(dotnet2.Bitmap bs);
		private ScreenDelegate updateScreenAction;
		private Thread getScreenshotThread;
		private bool getScreenShots;
		private bool runThread;
		

		public DialPad()
		{
			InitializeComponent();
			phoneLock = new object();
			showAsterisk = false;
			getScreenShots = false;
			runThread = true;

		
			this.btnClose.Click += new RoutedEventHandler(btnClose_Click);
			this.btnMinimze.Click += new RoutedEventHandler(btnMinimze_Click);
			this.btnVm.Click += new RoutedEventHandler(btnVm_Click);
			this.btnSvcs.Click += new RoutedEventHandler(btnSvcs_Click);
			this.btnUp.Click += new RoutedEventHandler(btnUp_Click);
			this.btnDown.Click += new RoutedEventHandler(btnDown_Click);
			this.btnVolDown.Click+=new RoutedEventHandler(btnVolDown_Click);
			this.btnVolUp.Click += new RoutedEventHandler(btnVolUp_Click);
			this.btnMute.Click += new RoutedEventHandler(btnMute_Click);
			this.btnStar.Click += new RoutedEventHandler(numPadButtonClick);
			this.btnPound.Click += new RoutedEventHandler(numPadButtonClick);
			this.btn0.Click += new RoutedEventHandler(numPadButtonClick);
			this.btn1.Click += new RoutedEventHandler(numPadButtonClick);
			this.btn2.Click += new RoutedEventHandler(numPadButtonClick);
			this.btn3.Click += new RoutedEventHandler(numPadButtonClick);
			this.btn4.Click += new RoutedEventHandler(numPadButtonClick);
			this.btn5.Click += new RoutedEventHandler(numPadButtonClick);
			this.btn6.Click += new RoutedEventHandler(numPadButtonClick);
			this.btn7.Click += new RoutedEventHandler(numPadButtonClick);
			this.btn8.Click += new RoutedEventHandler(numPadButtonClick);
			this.btn9.Click += new RoutedEventHandler(numPadButtonClick);
			this.KeyDown += new KeyEventHandler(DialPad_KeyDown);
			this.txtDialedDigits.KeyDown +=new KeyEventHandler(DialPad_KeyDown);

			this.btnSoftKey1.Click += new RoutedEventHandler(btnSoftKey1_Click);
			this.btnSoftKey2.Click += new RoutedEventHandler(btnSoftKey2_Click);
			this.btnSoftKey3.Click += new RoutedEventHandler(btnSoftKey3_Click);
			this.btnSoftKey4.Click += new RoutedEventHandler(btnSoftKey4_Click);

			this.lnkClear.MouseDown += new MouseButtonEventHandler(lnkClear_MouseDown);
			this.lnkClear.MouseEnter += new MouseEventHandler(lnkClear_MouseEnter);
			this.lnkClear.MouseLeave += new MouseEventHandler(lnkClear_MouseLeave);
			this.updateScreenAction = new ScreenDelegate(this.UpdateScreenAction);
					
			this.Closing += new System.ComponentModel.CancelEventHandler(DialPad_Closing);
			this.Loaded += new RoutedEventHandler(DialPad_Loaded);
			Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ":  Starting Thread");
			this.getScreenshotThread = new Thread(new ThreadStart(this.ScreenshotThread));
			Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ":  Thread Started");
			this.MouseLeftButtonUp += new MouseButtonEventHandler(DialPad_MouseLeftButtonUp);

			this.Activated += new EventHandler(DialPad_Activated);
		}


		void DialPad_Activated(object sender, EventArgs e)
		{
			if (this.WindowState == WindowState.Minimized)
			{
				this.WindowState = WindowState.Normal;
			}
		}

		void btnMinimze_Click(object sender, RoutedEventArgs e)
		{
			this.expanderScreen.IsExpanded = false;
			this.WindowState = WindowState.Minimized;
		}

		

		void DialPad_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
		{
			if (e.ChangedButton == MouseButton.Left)
			{
				this.AdjustScreenPosition();
			}
		}

		void AdjustScreenPosition()
		{
			//we need to make sure we are visible on the screen
			double ntop = Math.Min(Math.Max(this.Top, 0), SystemParameters.VirtualScreenHeight - (this.Height - 10));
			double nleft = Math.Min(Math.Max(this.Left, 0), SystemParameters.VirtualScreenWidth - (this.Width - 15));

			if (nleft != this.Left)
			{
				this.SetValue(Window.LeftProperty, nleft);
			}
			if (ntop != this.Top)
			{
				this.SetValue(Window.TopProperty, ntop);
			}
			if (DataStore.Instance.SaveScreenPosition)
			{
				DataStore.Instance.DialPadLastPosition = new Point(nleft, ntop);
			}
		}

		void DialPad_Loaded(object sender, RoutedEventArgs e)
		{
			Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ":  Loaded");
			if (DataStore.Instance.SaveScreenPosition)
			{
				Point location = DataStore.Instance.DialPadLastPosition;
				if (location.X != Double.MinValue && location.Y != Double.MinValue)
				{
					//we need to make sure we are visible on the screen
					this.Top = location.Y;
					this.Left = location.X;
					AdjustScreenPosition();
				}
			}
			this.getScreenshotThread.Start();
			this.Activate();
		}

		void ScreenshotThread()
		{
			try
			{
				Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ":  Thread Starting");
				DateTime started;
				while (runThread)
				{
					started = DateTime.Now;
					if (this.getScreenShots)
					{
						Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": Tick");
						dotnet2.Bitmap image = getScreenShot();
						if (image != null)
						{
							this.screenImage.Dispatcher.BeginInvoke(this.updateScreenAction, dotnet3Threading.DispatcherPriority.Render, new object[] { image });
						}
					}
					Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": Sleeping: " + (2000 - DateTime.Now.Subtract(started).Milliseconds).ToString());
					Thread.Sleep(2000 - DateTime.Now.Subtract(started).Milliseconds);
				}
			}
			catch (ThreadInterruptedException) { ;}
			catch (Exception ex)
			{
				Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": " + ex.Message);
			}
		}

		void DialPad_KeyDown(object sender, KeyEventArgs e)
		{
			if (e.Handled)
				return;
			Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ":  Processing KeyStroke");
			switch (e.Key)
			{
				case Key.D0:
					e.Handled = true;
					this.DialNumber("0");
					break;
				case Key.D1:
					e.Handled = true;
					this.DialNumber("1");
					break;
				case Key.D2:
					e.Handled = true;
					this.DialNumber("2");
					break;
				case Key.D3:
					if ((e.KeyboardDevice.Modifiers & ModifierKeys.Shift) == ModifierKeys.Shift)
					{
						e.Handled = true;
						this.DialNumber("#");
					}
					else
					{
						e.Handled = true;
						this.DialNumber("3");
					}
					break;
				case Key.D4:
					e.Handled = true;
					this.DialNumber("4");
					break;
				case Key.D5:
					e.Handled = true;
					this.DialNumber("5");
					break;
				case Key.D6:
					e.Handled = true;
					this.DialNumber("6");
					break;
				case Key.D7:
					e.Handled = true;
					this.DialNumber("7");
					break;
				case Key.D8:
					if ((e.KeyboardDevice.Modifiers & ModifierKeys.Shift) == ModifierKeys.Shift)
					{
						e.Handled = true;
						this.DialNumber("*");
					}
					else
					{
						e.Handled = true;
						this.DialNumber("8");
					}
					break;
				case Key.D9:
					e.Handled = true;
					this.DialNumber("9");
					break;
				case Key.NumPad0:
					e.Handled = true;
					this.DialNumber("0");
					break;
				case Key.NumPad1:
					e.Handled = true;
					this.DialNumber("1");
					break;
				case Key.NumPad2:
					e.Handled = true;
					this.DialNumber("2");
					break;
				case Key.NumPad3:
					e.Handled = true;
					this.DialNumber("3");
					break;
				case Key.NumPad4:
					e.Handled = true;
					this.DialNumber("4");
					break;
				case Key.NumPad5:
					e.Handled = true;
					this.DialNumber("5");
					break;
				case Key.NumPad6:
					e.Handled = true;
					this.DialNumber("6");
					break;
				case Key.NumPad7:
					e.Handled = true;
					this.DialNumber("7");
					break;
				case Key.NumPad8:
					e.Handled = true;
					this.DialNumber("8");
					break;
				case Key.NumPad9:
					e.Handled = true;
					this.DialNumber("9");
					break;
				case Key.Multiply:
					e.Handled = true;
					this.DialNumber("*");
					break;
				case Key.F1:
					e.Handled = true;
					this.DialNumber("Soft1");
					break;
				case Key.Enter:
					e.Handled = true;
					this.DialNumber("Soft2");
					break;
				case Key.F2:
					e.Handled = true;
					this.DialNumber("Soft2");
					break;
				case Key.F3:
					e.Handled = true;
					this.DialNumber("Soft3");
					break;
				case Key.F4:
					e.Handled = true;
					this.DialNumber("Soft4");
					break;
			}
		}

		void UpdateScreenAction(dotnet2.Bitmap image)
		{
			Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": Updating");
			try
			{
				Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ":  Calling CreateBitmapSourceFromHBitmap");
				BitmapSource bs = Imaging.CreateBitmapSourceFromHBitmap(image.GetHbitmap(), IntPtr.Zero, Int32Rect.Empty, BitmapSizeOptions.FromEmptyOptions());
				this.screenImage.Source = bs;
			}
			catch (Exception ex)
			{
				Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": " + ex.Message);
			}
		}

		void lnkClear_MouseLeave(object sender, MouseEventArgs e)
		{
			this.Cursor = Cursors.Arrow;
		}

		void lnkClear_MouseEnter(object sender, MouseEventArgs e)
		{
			this.Cursor = Cursors.Hand;
		}

		void lnkClear_MouseDown(object sender, MouseButtonEventArgs e)
		{
			this.txtDialedDigits.Text = "";
		}
		
		private dotnet2.Bitmap getScreenShot()
		{
			lock (this.phoneLock)
			{
				if (CDPListener.HaveAttachedPhones)
				{
					Dictionary<string, string> phones = CDPListener.AttachedPhones;
					foreach (KeyValuePair<string, string> kvp in phones)
					{
						try
						{
							dotnet2.Bitmap source = CiscoPhone.IpPhoneActions.GetScreenShotFromPhone(DataStore.Instance.UserId, DataStore.Instance.Password, kvp.Value);
							if (source != null)
							{
								return source;
							}
						}
						catch (Exception ex)
						{
							Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": " + ex.Message);
						}
						break;
					}
				}
			}
			
			return (dotnet2.Bitmap)null;
		}

		void btnClose_Click(object sender, RoutedEventArgs e)
		{
			this.Shutdown();
			this.Close();
		}

		void DialPad_Closing(object sender, System.ComponentModel.CancelEventArgs e)
		{
			this.Shutdown();
		}

		void Shutdown()
		{
			try
			{
				this.runThread = false;
				this.getScreenShots = false;
				if (this.getScreenshotThread != null && this.getScreenshotThread.ThreadState != System.Threading.ThreadState.Unstarted)
				{
					this.getScreenshotThread.Interrupt();
					this.getScreenshotThread.Join(2000);
				}
			}
			catch (Exception ex)
			{
				Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": " + ex.Message);
			}
		}

		void btnSoftKey4_Click(object sender, RoutedEventArgs e)
		{
			if (CDPListener.HaveAttachedPhones)
			{
				Dictionary<string, string> phones = CDPListener.AttachedPhones;
				foreach (KeyValuePair<string, string> kvp in phones)
				{
					IpPhoneActions.SendButton(DataStore.Instance.UserId, DataStore.Instance.Password, kvp.Value, "Soft4");
					break;
				}
			}
		}

		void btnSoftKey3_Click(object sender, RoutedEventArgs e)
		{
			if (CDPListener.HaveAttachedPhones)
			{
				Dictionary<string, string> phones = CDPListener.AttachedPhones;
				foreach (KeyValuePair<string, string> kvp in phones)
				{
					IpPhoneActions.SendButton(DataStore.Instance.UserId, DataStore.Instance.Password, kvp.Value, "Soft3");
					break;
				}
			}
		}

		void btnSoftKey2_Click(object sender, RoutedEventArgs e)
		{
			if (CDPListener.HaveAttachedPhones)
			{
				Dictionary<string, string> phones = CDPListener.AttachedPhones;
				foreach (KeyValuePair<string, string> kvp in phones)
				{
					IpPhoneActions.SendButton(DataStore.Instance.UserId, DataStore.Instance.Password, kvp.Value, "Soft2");
					break;
				}
			}
		}

		void btnSoftKey1_Click(object sender, RoutedEventArgs e)
		{
			if (CDPListener.HaveAttachedPhones)
			{
				Dictionary<string, string> phones = CDPListener.AttachedPhones;
				foreach (KeyValuePair<string, string> kvp in phones)
				{
					IpPhoneActions.SendButton(DataStore.Instance.UserId, DataStore.Instance.Password, kvp.Value, "Soft1");
					break;
				}
			}
		}

		void btnVm_Click(object sender, RoutedEventArgs e)
		{
			Debug.WriteLine(e.OriginalSource.ToString());
			this.txtDialedDigits.Text = "";
			if (CDPListener.HaveAttachedPhones)
			{
				this.showAsterisk = true;
				Dictionary<string, string> phones = CDPListener.AttachedPhones;
				foreach (KeyValuePair<string, string> kvp in phones)
				{
					IpPhoneActions.SendButton(DataStore.Instance.UserId, DataStore.Instance.Password, kvp.Value, "Messages");
					break;
				}
			}
		}
		void btnSvcs_Click(object sender, RoutedEventArgs e)
		{
			Debug.WriteLine(e.OriginalSource.ToString());
			this.txtDialedDigits.Text = "";
			if (CDPListener.HaveAttachedPhones)
			{
				Dictionary<string, string> phones = CDPListener.AttachedPhones;
				foreach (KeyValuePair<string, string> kvp in phones)
				{
					IpPhoneActions.SendButton(DataStore.Instance.UserId, DataStore.Instance.Password, kvp.Value, "Services");
					break;
				}

				if(!this.expanderScreen.IsExpanded)
					this.expanderScreen.IsExpanded = true;
			}
		}

		void btnDown_Click(object sender, RoutedEventArgs e)
		{
			Debug.WriteLine(e.OriginalSource.ToString());
			if (CDPListener.HaveAttachedPhones)
			{
				Dictionary<string, string> phones = CDPListener.AttachedPhones;
				foreach (KeyValuePair<string, string> kvp in phones)
				{
					IpPhoneActions.SendButton(DataStore.Instance.UserId, DataStore.Instance.Password, kvp.Value, "NavDwn");
					break;
				}
				this.expanderScreen.IsExpanded = true;
			}
		}

		void btnUp_Click(object sender, RoutedEventArgs e)
		{
			Debug.WriteLine(e.OriginalSource.ToString());
			if (CDPListener.HaveAttachedPhones)
			{
				Dictionary<string, string> phones = CDPListener.AttachedPhones;
				foreach (KeyValuePair<string, string> kvp in phones)
				{
					IpPhoneActions.SendButton(DataStore.Instance.UserId, DataStore.Instance.Password, kvp.Value, "NavUp");
					break;
				}
				this.expanderScreen.IsExpanded = true;
			}
		}

		void btnMute_Click(object sender, RoutedEventArgs e)
		{
			Debug.WriteLine(e.OriginalSource.ToString());
			if (CDPListener.HaveAttachedPhones)
			{
				Dictionary<string, string> phones = CDPListener.AttachedPhones;
				foreach (KeyValuePair<string, string> kvp in phones)
				{
					IpPhoneActions.SendButton(DataStore.Instance.UserId, DataStore.Instance.Password, kvp.Value, "Mute");
					break;
				}
			}
		}

		void btnVolUp_Click(object sender, RoutedEventArgs e)
		{
			Debug.WriteLine(e.OriginalSource.ToString());
			if (CDPListener.HaveAttachedPhones)
			{
				Dictionary<string, string> phones = CDPListener.AttachedPhones;
				foreach (KeyValuePair<string, string> kvp in phones)
				{
					IpPhoneActions.SendButton(DataStore.Instance.UserId, DataStore.Instance.Password, kvp.Value, "VolUp");
					break;
				}
			}
		}

		void btnVolDown_Click(object sender, RoutedEventArgs e)
		{
			Debug.WriteLine(e.OriginalSource.ToString());
			if (CDPListener.HaveAttachedPhones)
			{
				Dictionary<string, string> phones = CDPListener.AttachedPhones;
				foreach (KeyValuePair<string, string> kvp in phones)
				{
					IpPhoneActions.SendButton(DataStore.Instance.UserId, DataStore.Instance.Password, kvp.Value, "VolDwn");
					break;
				}
			}
		}

		void numPadButtonClick(object sender, RoutedEventArgs e)
		{
			try
			{
				string number = ((Button)e.OriginalSource).Content.ToString();
				Debug.WriteLine(number);
				this.DialNumber(number);
			}
			catch (Exception ex)
			{
				Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": " + ex.Message);
			}
		}

		void DialNumber(string number)
		{
			try
			{
				Debug.WriteLine(number);
				if (CDPListener.HaveAttachedPhones)
				{
					Dictionary<string, string> phones = CDPListener.AttachedPhones;
					foreach (KeyValuePair<string, string> kvp in phones)
					{
						IpPhoneActions.SendButton(DataStore.Instance.UserId, DataStore.Instance.Password, kvp.Value, number);
						break;
					}
				}
				if (number == "#")
				{
					this.showAsterisk = false;
				}
				if (!number.StartsWith("S")) //don't show softkeys
				{
					this.txtDialedDigits.Text += this.showAsterisk ? "X" : number;
				}
			}
			catch (Exception ex)
			{
				Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": " + ex.Message);
			}
		}

		private void expanderScreen_Collapsed(object sender, RoutedEventArgs e)
		{
			Debug.WriteLine("expanderScreen_Collapsed");
			try
			{
				this.OuterGrid.Height -= 150;
				this.Height -= 150;
				this.backgroundRectangle.Height -= 150;
				this.gridDialPad.Margin = new Thickness(this.gridDialPad.Margin.Left, this.gridDialPad.Margin.Top - 150, this.gridDialPad.Margin.Right, this.gridDialPad.Margin.Bottom);
				//this.gridUpDown.Margin = new Thickness(this.gridUpDown.Margin.Left, this.gridUpDown.Margin.Top - 150, this.gridUpDown.Margin.Right, this.gridUpDown.Margin.Bottom);
				this.gridUpDown.Visibility = Visibility.Collapsed;
				this.getScreenShots = false;
				Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": " + getScreenShots.ToString());
			}
			catch (Exception ex)
			{
				Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": " + ex.Message);
			}
		}

		private void expanderScreen_Expanded(object sender, RoutedEventArgs e)
		{
			Debug.WriteLine("expanderScreen_Expanded");
			try
			{
				this.getScreenShots = true;
				Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": " + getScreenShots.ToString());
				this.OuterGrid.Height += 150;
				this.Height += 150;
				this.backgroundRectangle.Height += 150;

				AdjustScreenPosition();
				Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ":  Resizing");
				this.gridDialPad.Margin = new Thickness(this.gridDialPad.Margin.Left, this.gridDialPad.Margin.Top + 150, this.gridDialPad.Margin.Right, this.gridDialPad.Margin.Bottom);
				//this.gridUpDown.Margin = new Thickness(this.gridUpDown.Margin.Left, this.gridUpDown.Margin.Top + 150, this.gridUpDown.Margin.Right, this.gridUpDown.Margin.Bottom);
				this.gridUpDown.Visibility = Visibility.Visible;
				Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ":  Resized");
			}
			catch (Exception ex)
			{
				Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": " + ex.Message);
			}
		}

		private void Window_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
		{
			DragMove();
		}
	}
}
