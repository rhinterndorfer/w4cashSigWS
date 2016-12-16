using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.ServiceModel;
using System.ServiceModel.Web;
using System.Text;

namespace w4cashSig
{
    [ServiceContract]
    public interface ISig
    {

        [OperationContract]
        string GetInfoZDAId();

        [OperationContract]
        byte[] GetInfoSigCert();

        [OperationContract]
        byte[] GetInfoIssuerCert();

        [OperationContract]
        byte[] Sign(byte[] ToBeSigned);

    }

}
