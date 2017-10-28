using System;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using System.Diagnostics;
using System.Globalization;


namespace WpfSearcher.Formatters
{
	public sealed class BackgroundConvertor : IValueConverter
	{
		public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
		{
			ListViewItem item = (ListViewItem)value;
			ListView listView = ItemsControl.ItemsControlFromItemContainer(item) as ListView;

			// Get the index of a ListViewItem
			int index = listView.ItemContainerGenerator.IndexFromContainer(item);
			if (index % 2 == 0)
			{
				return Brushes.LightBlue;
			}
			else
			{
				return Brushes.White;
			}
		}

		public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
		{
			throw new NotSupportedException();
		}
	}
}