
using System;
using System.Security.Cryptography.X509Certificates;

using Yubico.YubiKey.Piv;

using VNLib.Hashing.IdentityUtility;

namespace PkiAuthenticator
{
    /// <summary>
    /// Represents an authenticaion device, backed by hardware or software keys.
    /// </summary>
    public interface IAuthenticator : IJwtSignatureProvider, IDisposable
    {
        /// <summary>
        /// The signature algorithm the devices/keys support.
        /// </summary>
        PivAlgorithm KeyAlgorithm { get; }

        /// <summary>
        /// Gets the public/key certificate for the authenticator
        /// </summary>
        /// <returns>The certificate</returns>
        X509Certificate2 GetCertificate();

        /// <summary>
        /// Initialies the authenticator's assets required for performing 
        /// authentication functions.
        /// </summary>
        /// <returns>True if the authenticator was successfully initialized.</returns>
        bool Initialize();

        /// <summary>
        /// Writes the internal devices to the log output
        /// </summary>
        /// <returns>The exit code for the process, 0 if successful, non-zero if the operation failed</returns>
        int ListDevices();
    }
}