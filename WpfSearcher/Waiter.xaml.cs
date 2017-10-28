using System.Windows.Media.Animation;

namespace WpfSearcher
{
	/// <summary>
	/// Interaction logic for Waiter.xaml
	/// </summary>
	public partial class Waiter
	{
		private Storyboard board;
		public Waiter()
		{
			this.InitializeComponent();
			this.board = (Storyboard)this.Resources["Spin"];
		}


		public void Start()
		{
			this.board.Begin(this, true);
		}

		public void Stop()
		{
			this.board.Stop();
		}

	}

}