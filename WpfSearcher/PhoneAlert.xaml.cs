using System.Collections.ObjectModel;
using System.Windows;
using WPFTaskbarNotifier;

namespace WpfSearcher
{
	/// <summary>
	/// Interaction logic for PhoneAlert.xaml
	/// </summary>
	public partial class PhoneAlert : TaskbarNotifier
	{
		private ObservableCollection<NotifyObject> notifyContent;

		public PhoneAlert()
		{
			InitializeComponent();
			this.OpeningMilliseconds = 500;
			this.HidingMilliseconds = 500;
			this.StayOpenMilliseconds = 10000;
		}

		/// <summary>
		/// A collection of NotifyObjects that the main window can add to.
		/// </summary>
		public ObservableCollection<NotifyObject> NotifyContent
		{
			get
			{
				if (this.notifyContent == null)
				{
					// Not yet created.
					// Create it.
					this.NotifyContent = new ObservableCollection<NotifyObject>();
				}
				return this.notifyContent;
			}
			set
			{
				this.notifyContent = value;
			}
		}


		private void Button_Click(object sender, RoutedEventArgs e)
		{
			this.ForceHidden();
		}
	}

	/// <summary>
	/// This is just a mock object to hold something of interest. 
	/// </summary>
	public class NotifyObject
	{
		public NotifyObject(string message, string title)
		{
			this.message = message;
			this.title = title;
		}

		private string title;
		public string Title
		{
			get { return this.title; }
			set { this.title = value; }
		}

		private string message;
		public string Message
		{
			get { return this.message; }
			set { this.message = value; }
		}
	}
}