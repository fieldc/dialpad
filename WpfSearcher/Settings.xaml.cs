using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;
using System.Windows.Media.Animation;
using System.Windows.Media.Effects;
using System.Net;
using System.Reflection;
using System.Diagnostics;

namespace WpfSearcher
{
	/// <summary>
	/// Interaction logic for Settings.xaml
	/// </summary>
	public partial class Settings : Window
	{
		public Settings()
		{
			InitializeComponent();
			this.btnCancel.Click += new RoutedEventHandler(btnCancel_Click);
			this.btnClose.Click+=new RoutedEventHandler(btnCancel_Click);
			this.btnSave.Click += new RoutedEventHandler(btnSave_Click);	
			this.Loaded += new RoutedEventHandler(Settings_Loaded);
		
		}

		void Settings_MouseUp(object sender, MouseButtonEventArgs e)
		{
			if (e.ChangedButton == MouseButton.Left)
			{
				//we need to make sure we are visible on the screen
				double ntop = Math.Min(Math.Max(this.Top, 0), SystemParameters.VirtualScreenHeight - (this.Height-15));
				double nleft = Math.Min(Math.Max(this.Left, 0), SystemParameters.VirtualScreenWidth - (this.Width-20));

				if (DataStore.Instance.SaveScreenPosition)
				{
					DataStore.Instance.SettingsLastPosition = new Point(nleft, ntop);
				}
				if (nleft != this.Left)
				{
					this.SetValue(Window.LeftProperty, nleft);
				}
				if (ntop != this.Top)
				{
					this.SetValue(Window.TopProperty, ntop);
				}
			}
		}

		void Settings_Loaded(object sender, RoutedEventArgs e)
		{
			if (DataStore.Instance.SaveScreenPosition)
			{
				Point location = DataStore.Instance.SettingsLastPosition;
				if (location.X != Double.MinValue && location.Y != Double.MinValue)
				{
					//we need to make sure we are visible on the screen
					double ntop = Math.Min(Math.Max(location.Y, 0), SystemParameters.VirtualScreenHeight - (this.Height-15));
					double nleft = Math.Min(Math.Max(location.X, 0), SystemParameters.VirtualScreenWidth - (this.Width-20));
					this.Top = ntop;
					this.Left = nleft;
				}
			}
			if (!string.IsNullOrEmpty(DataStore.Instance.IpAddress))
			{
				this.txtIpAddress.Text = DataStore.Instance.IpAddress;
			}

			if (!string.IsNullOrEmpty(DataStore.Instance.UserId))
			{
				this.txtUserName.Text = DataStore.Instance.UserId;
			}

			if (!string.IsNullOrEmpty(DataStore.Instance.Password))
			{
				this.txtPassword.Password = DataStore.Instance.Password;
			}

			this.chkAutoDiscover.IsChecked = DataStore.Instance.DiscoverPhones;
			this.chkSavePosition.IsChecked = DataStore.Instance.SaveScreenPosition;
			this.Activate();
			this.MouseLeftButtonUp += new MouseButtonEventHandler(Settings_MouseUp);
			
		}

		void btnSave_Click(object sender, RoutedEventArgs e)
		{
			if (!string.IsNullOrEmpty(this.txtIpAddress.Text))
			{
				IPAddress parsed;
				if (IPAddress.TryParse(this.txtIpAddress.Text, out parsed))
				{
					DataStore.Instance.IpAddress = this.txtIpAddress.Text;
				}
			}
			else
			{
				DataStore.Instance.IpAddress = "";
			}

			if (!string.IsNullOrEmpty(this.txtUserName.Text))
			{
				DataStore.Instance.UserId = this.txtUserName.Text;
			}
			else
			{
				DataStore.Instance.UserId = "";
			}

			if (!string.IsNullOrEmpty(this.txtPassword.Password))
			{
				DataStore.Instance.Password = this.txtPassword.Password;
			}
			else
			{
				DataStore.Instance.Password = "";
			}

			DataStore.Instance.SaveScreenPosition = this.chkSavePosition.IsChecked.Value;
			DataStore.Instance.DiscoverPhones = this.chkAutoDiscover.IsChecked.Value;
			DataStore.Instance.Save();
			this.Close();
		}

		void btnCancel_Click(object sender, RoutedEventArgs e)
		{
			this.Close();
		}

		private void Window_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
		{
			try
			{
				DragMove();
			}
			catch (Exception ex)
			{
				Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ex.Message);				
			}
		}

		private void resetLink_Click(object sender, RoutedEventArgs e)
		{
			this.resetPositions.Visibility = Visibility.Hidden;
			DataStore.Instance.DialPadLastPosition = new Point(Double.MinValue, Double.MinValue);
			DataStore.Instance.SearcherLastPosition = new Point(Double.MinValue, Double.MinValue);
			DataStore.Instance.SettingsLastPosition = new Point(Double.MinValue, Double.MinValue); 
		}

		
	}
}
