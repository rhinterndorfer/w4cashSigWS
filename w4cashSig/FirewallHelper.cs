using NetFwTypeLib;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace w4cashSig
{
    public class FirewallHelper : IDisposable
    {
        private static FirewallHelper _instance;
        private INetFwPolicy2 _firewallPolicy;

        public static FirewallHelper Instance
        {
            get
            {
                if (_instance == null)
                    _instance = new FirewallHelper();
                return _instance;
            }
        }

        public FirewallHelper()
        {
            _firewallPolicy = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
        }

        public bool RuleActive(string ruleName)
        {
            return _firewallPolicy.Rules
                .Cast<INetFwRule>()
                .Any(r => (ruleName ?? String.Empty).Equals(r.Name)
                    && r.Enabled
                );
        }

        public void RuleBlockingActivate(string ruleName, string[] ports, string[] remoteIPaddresses, bool appendRemoteIPAddresses = true)
        {
            INetFwRule fwRule = _firewallPolicy
                .Rules
                .Cast<INetFwRule>()
                .FirstOrDefault(r => (ruleName ?? String.Empty).Equals(r.Name));

            if (fwRule == null)
            {
                fwRule = (INetFwRule)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule"));
                fwRule.Name = ruleName;
                _firewallPolicy.Rules.Add(fwRule);
            }

            // update rule
            fwRule.Direction = NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_OUT;
            fwRule.Action = NET_FW_ACTION_.NET_FW_ACTION_BLOCK;
            fwRule.Enabled = true;
            fwRule.Protocol = 6; // TCP 
            if (remoteIPaddresses != null)
            {
                string[] addressesTmp = remoteIPaddresses;
                if (appendRemoteIPAddresses 
                    && !String.IsNullOrEmpty(fwRule.RemoteAddresses) 
                    && fwRule.RemoteAddresses != "*")
                {
                    addressesTmp = remoteIPaddresses.Select(s => s + "/255.255.255.255").Concat(fwRule.RemoteAddresses.Split(',')).Distinct().ToArray();
                }

                fwRule.RemoteAddresses = string.Join(",", addressesTmp);
            }
            else
                fwRule.RemoteAddresses = string.Empty;

            if (ports != null)
            {
                fwRule.RemotePorts = string.Join(",", ports);
            }
            else
                fwRule.RemotePorts = string.Empty;
        }


        public void RuleInAcceptActivate(string ruleName, string[] ports)
        {
            INetFwRule fwRule = _firewallPolicy
                .Rules
                .Cast<INetFwRule>()
                .FirstOrDefault(r => (ruleName ?? String.Empty).Equals(r.Name));

            if (fwRule == null)
            {
                fwRule = (INetFwRule)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule"));
                fwRule.Name = ruleName;
                _firewallPolicy.Rules.Add(fwRule);
            }

            // update rule
            fwRule.Direction = NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_IN;
            fwRule.Action = NET_FW_ACTION_.NET_FW_ACTION_ALLOW;
            fwRule.Enabled = true;
            fwRule.Protocol = 6; // TCP 

            if (ports != null)
            {
                fwRule.LocalPorts = string.Join(",", ports);
            }
            else
                fwRule.LocalPorts = string.Empty;
        }


        public void RuleBlockingDeActivate(string ruleName)
        {
            INetFwRule fwRule = _firewallPolicy.Rules
                .Cast<INetFwRule>()
                .FirstOrDefault(r => (ruleName ?? String.Empty).Equals(r.Name));

            if (fwRule != null)
            {
                // update rule
                fwRule.Enabled = false;
            }


        }

        public void Dispose()
        {
            _firewallPolicy = null;
        }

    }

}
