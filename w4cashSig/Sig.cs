using Registrierkasse;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace w4cashSig
{
    public class Sig : ISig
    {

        static private bool isInitialised = false;
        static private string zdaId;
        static private X509Certificate sigCert;
        static private X509Certificate issuerCert;

        static public bool Initialise()
        {
            if (!isInitialised)
            {
                using (RKWrapper rkw = new RKWrapper())
                {
                    int ret = 0;

                    ret = rkw.GetInfo(out zdaId, out sigCert, out issuerCert);

                    if (ret == 0)
                    {
                        isInitialised = true;
                    }
                    else
                    {
                        isInitialised = false;
                    }
                }
            }
            return isInitialised;
        }

        public string GetInfoZDAId()
        {
            Initialise();
            return zdaId;
        }

        public byte[] GetInfoSigCert()
        {
            Initialise();
            return sigCert?.Export(X509ContentType.Cert);
        }

        public byte[] GetInfoIssuerCert()
        {
            Initialise();
            return issuerCert?.Export(X509ContentType.Cert);
        }

        public byte[] Sign(byte[] ToBeSigned)
        {
            using (RKWrapper rkw = new RKWrapper())
            {
                byte[] signature;
                int ret = rkw.Sign(ToBeSigned, out signature);

                if (ret == 0)
                {
                    return signature;
                }
                else
                {
                    return null;
                }
            }
        }
    }
}
