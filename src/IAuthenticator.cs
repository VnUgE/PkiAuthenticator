/*
* Copyright (c) 2023 Vaughn Nugent
* 
* Package: PkiAuthenticator
* File: IAuthenticator.cs 
*
* PkiAuthenticator is free software: you can redistribute it and/or modify 
* it under the terms of the GNU General Public License as published
* by the Free Software Foundation, either version 2 of the License,
* or (at your option) any later version.
*
* PkiAuthenticator is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
* General Public License for more details.
*
* You should have received a copy of the GNU General Public License 
* along with PkiAuthenticator. If not, see http://www.gnu.org/licenses/.
*/


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