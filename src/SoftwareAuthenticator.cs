/*
* Copyright (c) 2023 Vaughn Nugent
* 
* Package: PkiAuthenticator
* File: SoftwareAuthenticator.cs 
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
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using VNLib.Utils;
using VNLib.Utils.IO;
using VNLib.Utils.Logging;
using VNLib.Utils.Memory;

using Yubico.YubiKey.Piv;

using static PkiAuthenticator.Statics;

namespace PkiAuthenticator
{
    /// <summary>
    /// Provies a certificate/private key software based authenticator
    /// </summary>
    public sealed class SoftwareAuthenticator : VnDisposeable, IAuthenticator
    {
        private X509Certificate2? _certFile;
        private byte[]? _certFileData;

        ///<inheritdoc/>
        public PivAlgorithm KeyAlgorithm { get; private set; }
        public int RequiredBufferSize
        {
            get
            {
                return KeyAlgorithm switch
                {
                    PivAlgorithm.Rsa1024 => 128,
                    PivAlgorithm.Rsa2048 => 256,
                    PivAlgorithm.EccP256 => 128,
                    PivAlgorithm.EccP384 => 256,
                    _ => 128,
                };
            }
        }

        ///<inheritdoc/>
        public bool Initialize()
        {
            Log.Debug("Using software authenticator");

            //try to import the certificate file
            string? cerFilePath = CliArgs.GetArgument("--software");
            if(cerFilePath == null)
            {
                Log.Error("You must specify a file path following the --software flag");
                return false;
            }

            //Check if the file exists
            if (!FileOperations.FileExists(cerFilePath))
            {
                Log.Error("The certificate file does not exist");
                return false;
            }

            string? privateKeyFile = CliArgs.GetArgument("--private-key");

            if(privateKeyFile == null)
            {
                Log.Error("You must specify a private key pem file using the --private-key 'priv.pem' flag");
                return false;
            }

            //Confirm private key file exists
            if(!FileOperations.FileExists(privateKeyFile))
            {
                Log.Error("The private key file does not exist");
                return false;
            }

            ReadOnlySpan<char> password = null;

            //See if password is required
            if (CliArgs.HasArgument("--password"))
            {
                //encryption is required, get from arg, or from env var
                string? pass = CliArgs.GetArgument("--password") ?? Environment.GetEnvironmentVariable(Program.SOFTWARE_PASSWORD_VAR_NAME);

                if (pass == null)
                {
                    //if silent, we cant read the key, so we need to bail;
                    if (CliArgs.HasArgument("--silent") || CliArgs.HasArgument("-s"))
                    {
                        return false;
                    }

                    //Read key from stdin
                    Log.Information("Please enter your private key password");
                    pass = Console.ReadLine();
                }

                password = pass;
            }
          
            //file is a pem certificate
            try
            {
                //file is encrypted
                if (password.IsEmpty)
                {
                    Log.Debug("Importing raw pem/private key x509 certificate file");

                    //Non encrypted
                    _certFile = X509Certificate2.CreateFromPemFile(cerFilePath, privateKeyFile);
                }
                else
                {
                    Log.Debug("Importing encyrpted pem/private key x509 certificate file");
                    
                    //load and decrypt
                    _certFile = X509Certificate2.CreateFromEncryptedPemFile(cerFilePath, password, privateKeyFile);
                }

                //Get the raw file data 
                _certFileData = _certFile.GetRawCertData();

                //Try get rsa key, just get pubkey to discover alg info
                using(RSA? alg = _certFile.GetRSAPublicKey())
                {
                    if (alg != null)
                    {
                        switch (alg.KeySize)
                        {
                            case 1024:
                                KeyAlgorithm = PivAlgorithm.Rsa1024;
                                break;
                            case 2048:
                                KeyAlgorithm = PivAlgorithm.Rsa2048; 
                                break;
                            default:
                                Log.Error("The certificate uses an unspported keyalgorithm");
                                return false;
                        } 
                    }
                }

                //Try get ecdsa alg
                using(ECDsa? alg = _certFile.GetECDsaPublicKey())
                {
                    if (alg != null)
                    {
                        switch (alg.KeySize)
                        {
                            case 256:
                                KeyAlgorithm = PivAlgorithm.EccP256;
                                break;
                            case 384:
                                KeyAlgorithm = PivAlgorithm.EccP384;
                                break;
                            default:
                                Log.Error("The certificate uses an unspported keyalgorithm");
                                return false;
                        }
                    }
                }

                return true;
            }
            catch(Exception ex)
            {
                //Write the entire stack trace to the log if in debug mode
                if (Log.IsEnabled(LogLevel.Debug))
                {
                    Log.Error(ex);
                }
                else
                {
                    Log.Error("Failed to import the certificate file, reason {r}", ex.Message);
                }
            }

            return false;
        }

        ///<inheritdoc/>
        public X509Certificate2 GetCertificate()
        {
            Check();
            return new(_certFileData);
        }

        ///<inheritdoc/>
        public int ListDevices()
        {
            Log.Error("List devices is not supported in software mode");
            return -1;
        }

        protected override void Free()
        {
            //Dispose cert file
            _certFile?.Dispose();

            //Zero the cert file data buffer
            MemoryUtil.InitializeBlock(_certFileData.AsSpan());
        }

        HashAlgorithmName GetAlgName()
        {
            return KeyAlgorithm switch
            {
                PivAlgorithm.Rsa1024 => HashAlgorithmName.SHA256,//PS256
                PivAlgorithm.Rsa2048 => HashAlgorithmName.SHA256,//PS256
                PivAlgorithm.EccP256 => HashAlgorithmName.SHA256,//ES256
                PivAlgorithm.EccP384 => HashAlgorithmName.SHA384,//ES384
                _ => throw new NotSupportedException("Hash algorithim is not supported by this key"),
            };
        }

        ///<inheritdoc/>
        public ERRNO ComputeSignatureFromHash(ReadOnlySpan<byte> hash, Span<byte> outputBuffer)
        {
            Check();

            switch (KeyAlgorithm)
            {
                case PivAlgorithm.Rsa1024:
                case PivAlgorithm.Rsa2048:
                    {
                        //Try load private keys from cert
                        using RSA rsa = _certFile.GetRSAPrivateKey()!;

                        //Signs the data using sha256
                        if (!rsa.TrySignHash(hash, outputBuffer, GetAlgName(), RSASignaturePadding.Pkcs1, out int written))
                        {
                            throw new InternalBufferTooSmallException("");
                        }

                        return written;
                    }
                case PivAlgorithm.EccP256:
                case PivAlgorithm.EccP384:
                    {
                        using ECDsa ecc = _certFile.GetECDsaPrivateKey()!;

                        //Sign the digest
                        if (!ecc!.TrySignHash(hash, outputBuffer, DSASignatureFormat.IeeeP1363FixedFieldConcatenation, out int written))
                        {
                            throw new InternalBufferTooSmallException("");
                        }
                        return written;
                    }
                //This case should never be hit
                default:
                    throw new CryptographicException("Cannot sign data, the algorithm is unsupported");
            }
        }
    }
}
