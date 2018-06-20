using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Registrierkasse
{
    public class RKWrapperDomain : MarshalByRefObject, IRKWrapper
    {
        public int GetInfo(out string zdaId, out X509Certificate sigCert, out X509Certificate issCert)
        {
            lock (this)
            {
                int ret = -1;
                int retry = 3;

                do
                {
                    AppDomain dom = AppDomain.CreateDomain("GetInfoDomain");

                    try
                    {
                        RKWrapperDomain wrapper = (RKWrapperDomain)dom.CreateInstanceAndUnwrap(Assembly.GetAssembly(typeof(RKWrapperDomain)).FullName, typeof(RKWrapperDomain).FullName);
                        ret = wrapper.GetInfoInternal(out zdaId, out sigCert, out issCert);
                    }
                    finally
                    {
                        AppDomain.Unload(dom);
                    }
                    retry--;

                    if (retry >= 0 && ret != 0)
                        Thread.Sleep(500 * (3 - retry));

                } while (retry >= 0 && ret != 0);

                return ret;
            }
        }

        public int Sign(byte[] dataToSign, out byte[] signature)
        {
            lock (this)
            {
                int ret = -1;
                int retry = 3;

                do
                {
                    AppDomain dom = AppDomain.CreateDomain("GetSignDomain");
                    try
                    {
                        RKWrapperDomain wrapper = (RKWrapperDomain)dom.CreateInstanceAndUnwrap(Assembly.GetAssembly(typeof(RKWrapperDomain)).FullName, typeof(RKWrapperDomain).FullName);
                        ret = wrapper.GetSignInternal(dataToSign, out signature);
                    }
                    finally
                    {
                        AppDomain.Unload(dom);
                    }

                    retry--;

                    if (retry >= 0 && ret != 0)
                        Thread.Sleep(500 * (3 - retry));

                } while (retry >= 0 && ret != 0);

                return ret;
            }
        }


        public int GetInfoInternal(out string zdaId, out X509Certificate sigCert, out X509Certificate issCert)
        {
            var rkwrapper = new RKWrapper();
            int ret = rkwrapper.GetInfo(out zdaId, out sigCert, out issCert);
            return ret;
        }

        public int GetSignInternal(byte[] dataToSign, out byte[] signature)
        {
            var rkwrapper = new RKWrapper();
            int ret = rkwrapper.Sign(dataToSign, out signature);
            return ret;
        }



    }
}
