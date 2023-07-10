
using System;
using System.Threading;
using System.ServiceProcess;
using System.Windows.Forms;

namespace NoMoreCookiesService
{
    internal static class Program
    {
        private static NotifyIcon notifyIcon;

        static void Main()
        {
            //  NotifyIcon
            notifyIcon = new NotifyIcon();
            notifyIcon.Text = "NoMoreCookiesService";
            notifyIcon.Visible = true;

            // context NotifyIcon
            ContextMenuStrip contextMenu = new ContextMenuStrip();
            ToolStripMenuItem exitMenuItem = new ToolStripMenuItem("Exit");
            exitMenuItem.Click += ExitMenuItem_Click;
            contextMenu.Items.Add(exitMenuItem);
            notifyIcon.ContextMenuStrip = contextMenu;

            // double click
            notifyIcon.DoubleClick += NotifyIcon_DoubleClick;

            // start service
            ServiceBase[] ServicesToRun;
            ServicesToRun = new ServiceBase[]
            {
                new MainService()
            };
            ServiceBase.Run(ServicesToRun);

            // Infinity time
            Application.Run();
        }

        private static void ExitMenuItem_Click(object sender, EventArgs e)
        {
            // Exit
            notifyIcon.Visible = false;
            notifyIcon.Dispose();
            Application.Exit();
        }

        private static void NotifyIcon_DoubleClick(object sender, EventArgs e)
        {
           
        }
    }
}