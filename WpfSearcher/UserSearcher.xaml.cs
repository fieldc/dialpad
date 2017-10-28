using System;
using System.Text;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.IO;
using System.Reflection;
using System.Runtime.Remoting.Messaging;
using System.Windows;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Threading;
using WinForms = System.Windows.Forms;

namespace WpfSearcher
{
	public enum SearcherModes : short
	{
		SEARCH =1,
		DIAL = 2,
		INTLSEARCH = 3
	}
	/// <summary>
	/// Interaction logic for UserSearcher.xaml
	/// </summary>
	public partial class UserSearcher : Window
	{
		/// <summary>
		/// 
		/// </summary>
		/// <param name="searchText"></param>
		private delegate void SearcherDelegate(string searchText);
		/// <summary>
		/// 
		/// </summary>
		private SearcherDelegate doSearch;
		/// <summary>
		/// 
		/// </summary>
		/// <param name="results"></param>
		private delegate void DisplaySearchResultsDelegate(List<SearchResult> results);
		/// <summary>
		/// 
		/// </summary>
		private DisplaySearchResultsDelegate doResultDisplay;
		/// <summary>
		/// 
		/// </summary>
		/// <param name="phoneNumber"></param>
		private delegate void DialNumberDelegate(string phoneNumber);
		/// <summary>
		/// 
		/// </summary>
		private DialNumberDelegate doPhoneDial;

		/// <summary>
		/// 
		/// </summary>
		public delegate void SimpleDelegate();

		/// <summary>
		/// 
		/// </summary>
		private Searcher backend;
		/// <summary>
		/// 
		/// </summary>
		private bool isClosing;
		/// <summary>
		/// 
		/// </summary>
		private bool isSearching;
		
		/// <summary>
		/// 
		/// </summary>
		private Waiter wait;
		

		private SearcherModes mode;

		/// <summary>
		/// 
		/// </summary>
		public UserSearcher(SearcherModes mode)
		{
			InitializeComponent();
			this.mode = mode;
			backend = new Searcher();
			isClosing = false;
			isSearching = false;

			this.Closing += new System.ComponentModel.CancelEventHandler(UserSearcher_Closing);
			this.Loaded += new RoutedEventHandler(UserSearcher_Loaded);
			
			doSearch = new SearcherDelegate(this.StartSearch);
			doResultDisplay = new DisplaySearchResultsDelegate(this.DisplayResults);
			doPhoneDial = new DialNumberDelegate(this.DialNumber);

		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="sender"></param>
		/// <param name="e"></param>
		private void UserSearcher_Loaded(object sender, RoutedEventArgs e)
		{
			Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": Loading Form");
			if (DataStore.Instance.SaveScreenPosition)
			{
				Point location = DataStore.Instance.SearcherLastPosition;
				if (location.X != Double.MinValue && location.Y != Double.MinValue)
				{
					//we need to make sure we are visible on the screen
					double ntop = Math.Min(Math.Max(location.Y, 0), SystemParameters.VirtualScreenHeight - (this.Height - 12));
					double nleft = Math.Min(Math.Max(location.X, 0), SystemParameters.VirtualScreenWidth - (this.Width - 15));
					this.Top = ntop;
					this.Left = nleft;
				}
			}

			this.wait = new Waiter();
			this.LostKeyboardFocus += new KeyboardFocusChangedEventHandler(UserSearcher_LostKeyboardFocus);
			this.txtSearchFor.PreviewKeyDown += new KeyEventHandler(txtSearchFor_PreviewKeyDown);
			this.Dispatcher.BeginInvoke(DispatcherPriority.Input, new SimpleDelegate(delegate { txtSearchFor.Focus(); }));
			this.txtSearchFor.SelectAll();
			this.Activate();
			this.MouseLeftButtonUp += new MouseButtonEventHandler(UserSearcher_MouseLeftButtonUp);
		}

		void UserSearcher_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
		{
			if (e.ChangedButton == MouseButton.Left)
			{
				//we need to make sure we are visible on the screen
				double ntop = Math.Min(Math.Max(this.Top, 0), SystemParameters.VirtualScreenHeight - (this.Height-12));
				double nleft = Math.Min(Math.Max(this.Left, 0), SystemParameters.VirtualScreenWidth - (this.Width-15));

				if (DataStore.Instance.SaveScreenPosition)
				{
					DataStore.Instance.SearcherLastPosition = new Point(nleft, ntop);
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

		public void Shutdown()
		{
			if (this.ResultsDisplay.IsOpen)
			{
				this.ResultsDisplay.IsOpen = false;
				this.resultsList.Items.Clear();
			}
		}

		/// <summary>
		/// 
		/// </summary>
		public void HideForm()
		{
			
			if (this.isClosing || this.isSearching)
			{
				return;
			}
			this.Shutdown();
			this.Close();
			//this.Hide();
		}
		
		/// <summary>
		/// 
		/// </summary>
		/// <param name="searchText"></param>
		private void StartSearch(string searchText)
		{
			try
			{
				this.Dispatcher.BeginInvoke(DispatcherPriority.DataBind, new SimpleDelegate(delegate { this.OuterGrid.Children.Add(this.wait); this.wait.Start(); }));
				List<SearchResult> results = backend.Search(searchText);
				this.Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.DataBind, doResultDisplay, results);
			}
			catch (ArgumentNullException ane)
			{
				this.Dispatcher.BeginInvoke(DispatcherPriority.Input, new SimpleDelegate(delegate { MessageBox.Show(ane.Message); this.HandleResultsError(); }));
			}
			catch (Exception ex)
			{
				if (ex.InnerException != null)
				{
					this.Dispatcher.BeginInvoke(DispatcherPriority.Input, new SimpleDelegate(delegate { MessageBox.Show(ex.Message + ": " + ex.InnerException.Message); this.HandleResultsError(); }));
				}
				else
				{
					this.Dispatcher.BeginInvoke(DispatcherPriority.Input, new SimpleDelegate(delegate { MessageBox.Show(ex.Message); this.HandleResultsError(); }));
				}
			}
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="results"></param>
		private void DisplayResults(List<SearchResult> results)
		{
			this.Dispatcher.BeginInvoke(DispatcherPriority.DataBind, new SimpleDelegate(delegate { this.OuterGrid.Children.Remove(this.wait); }));
			if (results.Count == 0)
			{
				WinForms.MessageBox.Show("No Results Returned");
				this.ResultsDisplay.IsOpen = false;
			}
			else
			{
				this.resultsList.Items.Clear();
				results.Sort(new Comparison<SearchResult>(SearchResult.Compare));
				foreach (SearchResult result in results)
				{
					Debug.WriteLine(result.Name);
					this.resultsList.Items.Add(result);
				}
				this.ResultsDisplay.IsOpen = true;
				this.ResultsDisplay.StaysOpen = false;
			}
			
			this.isSearching = false;
		}

		private void HandleResultsError()
		{
			this.Dispatcher.BeginInvoke(DispatcherPriority.DataBind, new SimpleDelegate(delegate { this.OuterGrid.Children.Remove(this.wait); }));
			this.ResultsDisplay.IsOpen = false;
			this.isSearching = false;
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="ar"></param>
		private void GenericAsyncCallBack(IAsyncResult ar)
		{
			try
			{
				Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": Called back");
				if (((AsyncResult)ar).AsyncDelegate is SearcherDelegate)
				{
					SearcherDelegate sd = (SearcherDelegate)((AsyncResult)ar).AsyncDelegate;
					if (sd != null)
					{
						sd.EndInvoke(ar);
					}
				}
				else if (((AsyncResult)ar).AsyncDelegate is DialNumberDelegate)
				{
					DialNumberDelegate dd = (DialNumberDelegate)((AsyncResult)ar).AsyncDelegate;
					if (dd != null)
					{
						dd.EndInvoke(ar);
					}
				}
				else
				{
					throw new Exception("Invalid Callback Use");
				}
			}
			catch (Exception e)
			{
				MessageBox.Show("Unknown Async Exception: " + e.Message);
			}
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="sender"></param>
		/// <param name="e"></param>
		/// 
		void txtSearchFor_PreviewKeyDown(object sender, KeyEventArgs e)
		{
			Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": KeyDown: " + e.Key.ToString());
			if (e.Key == Key.Escape)
			{
				this.HideForm();
				e.Handled = true;
				return;
			}
			else if (e.Key == Key.Enter || e.Key == Key.Return)
			{
				if (this.isSearching || string.IsNullOrEmpty(this.txtSearchFor.Text.Trim()))
				{
					return;
				}

				e.Handled = true;
				if (this.txtSearchFor.Text.StartsWith("d:") || this.mode== SearcherModes.DIAL)
				{
					//dial short cut
					object state = new object();
					AsyncCallback cb = new AsyncCallback(this.GenericAsyncCallBack);
					this.doPhoneDial.BeginInvoke(PhoneNumberFormatter.FormatURL(this.txtSearchFor.Text), cb, state);
					this.HideForm();
				}
				else if(this.mode==SearcherModes.SEARCH)
				{
					this.isSearching = true;
					object state = new object();
					this.doSearch.BeginInvoke(this.txtSearchFor.Text, new AsyncCallback(this.GenericAsyncCallBack), state);
				}
				return;
			}

			return;
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="sender"></param>
		/// <param name="e"></param>
		private void UserSearcher_LostKeyboardFocus(object sender, KeyboardFocusChangedEventArgs e)
		{
			if (this.IsActive)
			{
				return;
			}
			
			///A-lo doesn't like th auto hide
			//this.HideForm();
			return;
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="sender"></param>
		/// <param name="e"></param>
		private void UserSearcher_Closing(object sender, System.ComponentModel.CancelEventArgs e)
		{
			this.isClosing = true;
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="sender"></param>
		/// <param name="e"></param>
		private void btnClose_Click(object sender, RoutedEventArgs e)
		{
			this.HideForm();
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="sender"></param>
		/// <param name="e"></param>
		private void Window_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
		{
			DragMove();
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="sender"></param>
		/// <param name="e"></param>
		private void UrlHyperlink_Click(object sender, RoutedEventArgs e)
		{
			if(e.Source is Hyperlink)
			{
				if (((Hyperlink)e.Source).Name.Equals("PhoneURL"))
				{
					object state = new object();
					AsyncCallback cb = new AsyncCallback(this.GenericAsyncCallBack);
					this.doPhoneDial.BeginInvoke(((Hyperlink)e.Source).NavigateUri.OriginalString,cb,state);
				}
				else
				{
					System.Console.WriteLine("Clicked: " + ((Hyperlink)e.Source).Name);
					ProcessStartInfo psInfo = new ProcessStartInfo(((Hyperlink)e.Source).NavigateUri.AbsoluteUri);
					psInfo.UseShellExecute = true;
					Process process = System.Diagnostics.Process.Start(psInfo);
				}

				this.HideForm();
			}
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="dialURL"></param>
		private void DialNumber(string dialURL)
		{
			try
			{
				if (CDPListener.HaveAttachedPhones)
				{
					Dictionary<string, string> phones = CDPListener.AttachedPhones;
					foreach (KeyValuePair<string, string> kvp in phones)
					{

						string body = String.Format("XML=<CiscoIPPhoneExecute><ExecuteItem URL=\"Dial:{0}\"/></CiscoIPPhoneExecute>",dialURL);
						Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": DialingURL: " + dialURL + " to Phone IP: " + kvp.Value);
						//dialURL += "&p=" + kvp.Value;
						string phoneUrl = string.Format("http://{0}/CGI/Execute", kvp.Value);
						HttpWebRequest request = (HttpWebRequest)HttpWebRequest.Create(phoneUrl);
						request.Credentials = new NetworkCredential(DataStore.Instance.UserId, DataStore.Instance.Password);
						Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": " + DataStore.Instance.UserId + "=" + DataStore.Instance.Password);
						request.Method = "POST";
						request.KeepAlive = true;
						request.PreAuthenticate = true;
						byte[] data = Encoding.ASCII.GetBytes(body);
						
						Stream requestStream = request.GetRequestStream();
						requestStream.Write(data, 0, data.Length);
						requestStream.Close();

						WebResponse response = request.GetResponse();
						response.Close();
						break;
					}
				}
				else
				{
					Debug.WriteLine(MethodBase.GetCurrentMethod().Name + ": No Phones Attached");
				}
			}
			catch (Exception e)
			{
				MessageBox.Show(e.Message);
			}
		}
	}
}
