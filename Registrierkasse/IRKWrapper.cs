using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Registrierkasse
{
    public interface IRKWrapper
    {
        int GetInfo(out string zdaId, out X509Certificate sigCert, out X509Certificate issCert);
        int Sign(byte[] dataToSign, out byte[] signature);
    }
}
