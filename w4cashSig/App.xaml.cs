using Registrierkasse;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.Linq;
using System.Reflection;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;

namespace w4cashSig
{
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>
    public partial class App : Application
    {
        private ServiceHost host;

        private void Application_Startup(object sender, StartupEventArgs e)
        {
            // Check Firewall Rule for inbound HTTP port
            if (!FirewallHelper.Instance.RuleActive("HTTP in (80)"))
            {
                if (!WindowsHelper.RunAsAdministrator())
                {
                    Application.Current.Shutdown();
                    return;
                }

                FirewallHelper.Instance.RuleInAcceptActivate("HTTP in (80)", new string[] { "80" });
            }

            StartHost();
        }


        private void StartHost()
        {
            Uri baseAddress = new Uri("http://localhost:80/Temporary_Listen_Addresses/w4cashSig");

            // Create the ServiceHost.
            host = new ServiceHost(typeof(Sig), baseAddress);

            // Enable metadata publishing.
            ServiceMetadataBehavior smb = new ServiceMetadataBehavior();
            smb.HttpGetEnabled = true;
            smb.MetadataExporter.PolicyVersion = PolicyVersion.Policy15;
            host.Description.Behaviors.Add(smb);

            //host.AddServiceEndpoint(typeof(ISig), new WebHttpBinding(), "").Behaviors.Add(new WebHttpBehavior());

            // Open the ServiceHost to start listening for messages. Since
            // no endpoints are explicitly configured, the runtime will create
            // one endpoint per base address for each service contract implemented
            // by the service.
            host.Open();
        }

        private void Application_Exit(object sender, ExitEventArgs e)
        {
            // Close the ServiceHost.
            if(host != null)
                host.Close();
        }
    }
}
