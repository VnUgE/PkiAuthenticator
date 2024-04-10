/*
* Copyright (c) 2023 Vaughn Nugent
* 
* Package: PkiAuthenticator
* File: Statics.cs 
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
using System.Linq;
using System.Text;
using System.Buffers;
using System.Text.Json;
using System.Buffers.Text;
using System.Runtime.CompilerServices;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Serilog;
using Serilog.Core;
using Serilog.Events;

using Yubico.YubiKey.Piv;

using VNLib.Utils;
using VNLib.Utils.Logging;
using VNLib.Utils.Memory;
using VNLib.Utils.Extensions;
using VNLib.Hashing;
using VNLib.Hashing.IdentityUtility;

namespace PkiAuthenticator
{

    internal static class Statics
    {
        public static ArgumentList CliArgs { get; } = new ArgumentList(Environment.GetCommandLineArgs());

        public static ILogProvider Log { get; } = GetLog();

        private static ILogProvider GetLog()
        {
            LoggerConfiguration config = new();

            //Set min level from cli flags
            if(CliArgs.HasArgument("--verbose") || CliArgs.HasArgument("-v"))
            {
                config.MinimumLevel.Verbose();
            }
            else if (CliArgs.HasArgument("--verbose") || CliArgs.HasArgument("-v"))
            {
                config.MinimumLevel.Debug();
            }
            else
            {
                config.MinimumLevel.Information();
            }

            //Make sure the silent flag is not set
            if(!CliArgs.HasArgument("--silent") || CliArgs.HasArgument("-s"))
            {
                //Write to console for now
                config.WriteTo.Console();
            }

            //Init new log
            return new VLogProvider(config);
        }

        /// <summary>
        /// Generats a signed VNLib authentication toke, used to authenticate against 
        /// web applications using the YubiKey
        /// </summary>
        /// <returns>The process exit code returning the status of the operation.</returns>
        public static int GenerateOtp(this IAuthenticator authenticator)
        {
            string? uid = CliArgs.GetArgument("-u");
            uid ??= CliArgs.GetArgument("--user");

            string? dataToSign = null;
            if (CliArgs.HasArgument("--sign"))
            {
                Log.Information("Enter the data to sign: ");
                dataToSign = Console.ReadLine();
            }

            HashAlg digest;

            //Init the jwt header
            Dictionary<string, string> jwtHeader = new()
            {
                ["typ"] = "jwt"
            };

            Log.Verbose("Recovering the device metadata...");

            switch (authenticator.KeyAlgorithm)
            {
                case PivAlgorithm.Rsa1024:
                case PivAlgorithm.Rsa2048:
                    //Use rsa256 for all rsa operations
                    digest = HashAlg.SHA256;
                    jwtHeader["alg"] = "RS256";
                    break;
                case PivAlgorithm.EccP256:
                    digest = HashAlg.SHA256;
                    jwtHeader["alg"] = "ES256";
                    break;
                case PivAlgorithm.EccP384:
                    digest = HashAlg.SHA384;
                    jwtHeader["alg"] = "ES384";
                    break;
                default:
                    Log.Error("The key's authentication slot contains an unsupported algorithm");
                    return -5;
            }

            //Build the login jwt
            using JsonWebToken jwt = new();

            jwt.WriteHeader(jwtHeader);

            Log.Verbose("Recovering the x509 certificate from the key");

            //Get the auth certificate
            using (X509Certificate2 cert = authenticator.GetCertificate())
            {
                //Default uid is the subjet name
                uid ??= cert.SubjectName.Name.AsSpan().SliceAfterParam("=").ToString();
             
                jwt.InitPayloadClaim()
                  .AddClaim("sub", uid)
                  .AddClaim("n", RandomHash.GetRandomBase32(16))
                  .AddClaim("iat", DateTimeOffset.UtcNow.ToUnixTimeSeconds())
                  //Keyid is the hex sha1 of the certificate
                  .AddClaim("keyid", Convert.ToHexString(cert.GetCertHash(HashAlgorithmName.SHA1)))
                  .AddClaim("serial", cert.SerialNumber)
                  .AddClaim("data", dataToSign!)
                  .CommitClaims();
            }

            Log.Verbose("Signing authentication token...");

            try
            {
                //Sign the token
                jwt.Sign(authenticator, digest);

                Log.Information(Program.TOKEN_PRINT_TEMPLATE, jwt.Compile());

                //If silent mode is enabled, write credential directly to stdout
                if (CliArgs.HasArgument("--silent") || CliArgs.HasArgument("-s"))
                {
                    Console.Write(jwt.Compile());
                }

                return 0;
            }
            catch (OperationCanceledException)
            {
                Log.Error("The operation has been cancelled");
                return -1;
            }
        }

        /// <summary>
        /// Base64url encodes the data buffer and returns a utf8 string from 
        /// the encoded results.
        /// </summary>
        /// <param name="data">The binary buffer to encode</param>
        /// <returns>The encoded string</returns>
        public static string ToBase64Url(ReadOnlySpan<byte> data)
        {
            int base64 = Base64.GetMaxEncodedToUtf8Length(data.Length);

            //Alloc buffer
            using UnsafeMemoryHandle<byte> buffer = MemoryUtil.UnsafeAllocNearestPage<byte>(base64);

            int written = ToBase64Url(data, buffer.Span);

            return Encoding.UTF8.GetString(buffer.Span[..written]);
        }

        /// <summary>
        /// Base64url encodes the data buffer and writes the output to the <paramref name="writer"/>
        /// argument.
        /// </summary>
        /// <param name="data">The binary data to base64url encode</param>
        /// <param name="writer">A referrence to the <see cref="ForwardOnlyWriter{T}"/></param>
        /// <exception cref="Exception"></exception>
        public static void ToUrlSafe(ReadOnlySpan<byte> data, ref ForwardOnlyWriter<byte> writer)
        {
            int base64Size = Base64.GetMaxEncodedToUtf8Length(data.Length);

            //Alloc buffer
            using UnsafeMemoryHandle<byte> buffer = MemoryUtil.UnsafeAllocNearestPage<byte>(base64Size);

            //Convert the data to base64url safe
            int written = ToBase64Url(data, buffer.Span);

            if(written == ERRNO.E_FAIL)
            {
                throw new Exception($"Failed to encode the binary data due to a base64 encoding failure");
            }

            //Write encoded data to writer
            writer.Append(buffer.Span[..written]);
        }

        /// <summary>
        /// Base64url encodes the data buffer and writes the output to the output buffer.
        /// </summary>
        /// <param name="data"></param>
        /// <param name="buffer">The output buffer to write the base64url encoded utf8 bytes</param>
        /// <returns>The number of bytes written to the output buffer, or 0/false if the operation failed</returns>
        /// <exception cref="Exception"></exception>
        public static ERRNO ToBase64Url(ReadOnlySpan<byte> data, Span<byte> buffer)
        {
            //Encode the data to base64
            OperationStatus status = Base64.EncodeToUtf8(data, buffer, out _, out int written, true);
            
            if (status != OperationStatus.Done)
            {
                return ERRNO.E_FAIL;
            }

            //Url encode
            VnEncoding.Base64ToUrlSafeInPlace(buffer[..written]);

            //Remove trailing padding bytes
            while (buffer[written - 1] == (byte)'=')
            {
                written--;
            }

            return written;
        }

        /// <summary>
        /// Writes the public key information for the current session, using the 
        /// configured slot, to a JWK, setting the key-id (kid) as the as the 
        /// hex encoded hash of the certificate.
        /// </summary>
        /// <param name="authenticator"></param>
        /// <returns>The process exit code, 0 if successful, non-zero if a failure occured</returns>
        public static string? ExportJwk(this IAuthenticator authenticator)
        {
            static void WriteEcParams(X509Certificate2 cert, IDictionary<string, string> jwk)
            {
                using ECDsa alg = cert.GetECDsaPublicKey()!;

                //recover params
                ECParameters p = alg.ExportParameters(false);

                //Write public key elements
                jwk["x"] = ToBase64Url(p.Q.X);
                jwk["y"] = ToBase64Url(p.Q.Y);
            }

            static void WriteRsaParams(X509Certificate2 cert, IDictionary<string, string> jwk)
            {
                using RSA rSA = cert.GetRSAPublicKey()!;

                RSAParameters p = rSA.ExportParameters(false);

                jwk["e"] = ToBase64Url(p.Exponent);
                jwk["n"] = ToBase64Url(p.Modulus);
            }

            Dictionary<string, string> jwkObj = new()
            {
                { "use", "sig" }
            };

            //Get key certificate
            using X509Certificate2 cert = authenticator.GetCertificate();

            //Write cert hash to the kid
            jwkObj["kid"] = Convert.ToHexString(cert.GetCertHash(HashAlgorithmName.SHA1));

            //Write cert serial number
            jwkObj["serial"] = cert.SerialNumber;

            switch (authenticator.KeyAlgorithm)
            {
                case PivAlgorithm.EccP256:
                    jwkObj["kty"] = "EC";
                    jwkObj["crv"] = "P-256";
                    jwkObj["alg"] = "ES256";

                    //write the ec params to jwk
                    WriteEcParams(cert, jwkObj);
                    break;
                case PivAlgorithm.EccP384:
                    jwkObj["kty"] = "EC";
                    jwkObj["crv"] = "P-384";
                    jwkObj["alg"] = "ES384";

                    //write the ec params to jwk
                    WriteEcParams(cert, jwkObj);
                    break;

                case PivAlgorithm.Rsa1024:
                case PivAlgorithm.Rsa2048:
                    jwkObj["kty"] = "RSA";
                    jwkObj["alg"] = "RS256";

                    //Rsa print
                    WriteRsaParams(cert, jwkObj);
                    break;

                default:
                    return null;
            }

            //Write jwk to std out
            return JsonSerializer.Serialize(jwkObj);
        }

        /// <summary>
        /// Writes the public key information for the current session, using the 
        /// configured slot, using PEM encoding.
        /// </summary>
        /// <param name="authenticator"></param>
        /// <returns>The process exit code, 0 if successful, non-zero if a failure occured</returns>
        public static string ExportPem(this IAuthenticator authenticator)
        {
            //Get key certificate
            using X509Certificate2 cert = authenticator.GetCertificate();

            byte[] pubkey = cert.PublicKey.ExportSubjectPublicKeyInfo();

            //Sb for printing cert data
            StringBuilder builder = new ();
            builder.AppendLine("-----BEGIN PUBLIC KEY-----");
            builder.AppendLine(Convert.ToBase64String(pubkey, Base64FormattingOptions.InsertLineBreaks));
            builder.AppendLine("-----END PUBLIC KEY-----");

            return builder.ToString();
        }

        private sealed class VLogProvider : VnDisposeable, ILogProvider
        {
            private readonly Logger LogCore;

            public VLogProvider(LoggerConfiguration config)
            {
                LogCore = config.CreateLogger();
            }
            public void Flush() { }

            public object GetLogProvider() => LogCore;

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public bool IsEnabled(LogLevel level) => LogCore.IsEnabled((LogEventLevel)level);

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public void Write(LogLevel level, string value)
            {
                LogCore.Write((LogEventLevel)level, value);
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public void Write(LogLevel level, Exception exception, string value = "")
            {
                LogCore.Write((LogEventLevel)level, exception, value);
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public void Write(LogLevel level, string value, params object[] args)
            {
                LogCore.Write((LogEventLevel)level, value, args);
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public void Write(LogLevel level, string value, params ValueType[] args)
            {
                //Serilog logger supports passing valuetypes to avoid boxing objects
                if (LogCore.IsEnabled((LogEventLevel)level))
                {
                    object[] ar = args.Select(a => (object)a).ToArray();
                    LogCore.Write((LogEventLevel)level, value, ar);
                }
            }

            protected override void Free() => LogCore.Dispose();
        }
    }
}
