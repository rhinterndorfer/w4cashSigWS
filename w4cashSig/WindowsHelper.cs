using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace w4cashSig
{
    public class WindowsHelper
    {
        public static bool RunAsAdministrator()
        {
            bool isAdmin = IsAdministrator();

            if (!isAdmin)
            {
                ProcessStartInfo processStartInfo = new ProcessStartInfo();
                processStartInfo.FileName = Assembly.GetEntryAssembly().Location;
                processStartInfo.UseShellExecute = true;
                processStartInfo.Verb = "runas";
                Process.Start(processStartInfo);
            }
            return isAdmin;
        }

        public static bool IsAdministrator()
        {
            bool isAdmin;
            try
            {
                WindowsIdentity user = WindowsIdentity.GetCurrent();
                WindowsPrincipal principal = new WindowsPrincipal(user);
                isAdmin = principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch (UnauthorizedAccessException)
            {
                isAdmin = false;
            }
            catch (Exception)
            {
                isAdmin = false;
            }

            return isAdmin;
        }
    }
}
