using Registrierkasse;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
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
        static private string lastError;
        static private string lastErrorExceptionMessage;

        private static void SetLastError(string error, string exceptionMessage = null)
        {
            lastError = error;
            lastErrorExceptionMessage = exceptionMessage;


            try
            {
                string fileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "RKSV.log");
                using (var sw = File.AppendText(fileName))
                {
                    sw.WriteLine(DateTime.Now.ToString("dd.MM.yyyy HH:mm:ss"));
                    sw.WriteLine(error);
                    if (exceptionMessage != null)
                        sw.WriteLine(exceptionMessage);
                }
            }
            catch (Exception)
            {
                // do nothing
            }
        }

        public static bool Initialise()
        {
            if (!isInitialised)
            {
                try
                {
                    RKWrapperDomain rkw = new RKWrapperDomain();

                    int ret = 0;

                    ret = rkw.GetInfo(out zdaId, out sigCert, out issuerCert);

                    if (ret == 0)
                    {
                        isInitialised = true;
                    }
                    else
                    {
                        SetLastError("Initialise.GetInfoFailed");
                        isInitialised = false;

                    }
                }
                catch (Exception ex)
                {
                    SetLastError("Initialise", ex.Message);
                }

            }
            return isInitialised;
        }

        private static bool VerifyData(byte[] data, byte[] signature)
        {
            X509Certificate2 cer = new X509Certificate2(sigCert);
            var pk = cer.GetECDsaPublicKey();
            bool verified = false;
            try
            {
                verified = pk.VerifyData(data, signature, HashAlgorithmName.SHA256);
            }
            catch (Exception ex)
            {
                SetLastError("VerifyData.VerifyDataException", ex.Message);
            }

            if (!verified)
            {
                SetLastError("VerifyData.VerifyDataFailed");
            }
            return verified;
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
            Initialise();

            try
            {
                RKWrapperDomain rkw = new RKWrapperDomain();

                byte[] signature;
                int ret = rkw.Sign(ToBeSigned, out signature);
                if (ret != 0)
                    SetLastError("Sign.SignFailed");

                if (ret == 0 && VerifyData(ToBeSigned, signature))
                {
                    return signature;
                }
                else
                {
                    isInitialised = false;
                    return null;
                }
            }
            catch (Exception ex)
            {
                SetLastError("Sign", ex.Message);
                isInitialised = false;
                return null;
            }
        }
    }
}
