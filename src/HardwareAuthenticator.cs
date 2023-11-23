/*
* Copyright (c) 2023 Vaughn Nugent
* 
* Package: PkiAuthenticator
* File: HardwareAuthenticator.cs 
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
using System.Formats.Asn1;
using System.Globalization;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

using Yubico.YubiKey;
using Yubico.YubiKey.Piv;

using VNLib.Utils;
using VNLib.Utils.Logging;
using VNLib.Utils.Extensions;

using static PkiAuthenticator.Statics;

namespace PkiAuthenticator
{
    /// <summary>
    /// Implements a hardware backed authenticator device using YubiKey's
    /// </summary>
    public sealed class HardwareAuthenticator : VnDisposeable, IAuthenticator
    {
     
        /*
        * Determines the piv slot the user may manually select
        * the slot nuber (in hex) or the default 
        * Authentication slot
        */

        private static byte PivSlot
        {
            get
            {
                //Check for slot cli flag
                string? slotArg = CliArgs.GetArgument("--piv-slot");
                //Try hase from hex, otherwise default to the authentication slot
                return byte.TryParse(slotArg, NumberStyles.HexNumber, null, out byte slotNum) ? slotNum : Yubico.YubiKey.Piv.PivSlot.Authentication;
            }
        }

        private PivSession? _session;

        ///<inheritdoc/>
        public PivAlgorithm KeyAlgorithm { get; private set; }

        public int RequiredBufferSize { get; }

        ///<inheritdoc/>
        public bool Initialize()
        {
            IYubiKeyDevice? device;

            Log.Debug("Using hardware authenticator");

            //User may select the serial of the specific key to use
            if (CliArgs.HasArgument("--key") && int.TryParse(CliArgs.GetArgument("--key"), out int serial))
            {
                Log.Debug("Loading device {d}", serial);

                //Get device by serial number
                device = YubiKeyDevice.FindAll()
                    .Where(d => d.SerialNumber == serial && d.HasFeature(YubiKeyFeature.PivApplication))
                    .FirstOrDefault();
            }
            else
            {
                Log.Debug("Connecting to first discovered PIV supported yubikey");

                //Get first piv device
                device = YubiKeyDevice.FindAll()
                            .Where(static d => d.HasFeature(YubiKeyFeature.PivApplication))
                            .FirstOrDefault();
            }

            if (device == null)
            {
                return false;
            }
            try
            {
                //Init PIV session
                _session = new(device)
                {
                    KeyCollector = GetUserPinInput
                };

                Log.Information("Connected to device {id}, using slot {slot}", device.SerialNumber!, PivSlot.ToString("x"));

                //Store the key algorithm
                KeyAlgorithm = _session.GetMetadata(PivSlot).Algorithm;

                return true;
            }
            catch (Exception ex) 
            {
                if (Log.IsEnabled(LogLevel.Debug))
                {
                    Log.Error(ex);
                }
                else
                {
                    Log.Error("Failed to initialize your hardware authenticator. Reason {r}", ex.Message);
                }

                return false;
            }
        }

        ///<inheritdoc/>
        public int ListDevices()
        {
            Log.Debug("Discovering hardware devices...");

            IEnumerable<IYubiKeyDevice> devices = YubiKeyDevice.FindAll();

            string[] devIds = devices
                    .Select(d => $"Serial: {d.SerialNumber}, Firmware {d.FirmwareVersion}, Formfactor: {d.FormFactor}, PIV support?: {d.HasFeature(YubiKeyFeature.PivApplication)}")
                    .ToArray();

            Log.Information("Found devices\n {dev}", devIds);

            return 0;
        }

        ///<inheritdoc/>
        public X509Certificate2 GetCertificate() =>
            _session?.GetCertificate(PivSlot)
            ?? throw new InvalidOperationException("The PIV session has not been successfully initialized");

        ///<inheritdoc/>
        protected override void Free()
        {
            _session?.Dispose();
        }

        static bool GetUserPinInput(KeyEntryData keyData)
        {
            //Method may be called more than once during pin operation, we only need to prompt for pins
            if (keyData.Request != KeyEntryRequest.VerifyPivPin)
            {
                return false;
            }

            string? input;

            //Check if the user issued the pin as cli arg
            if (CliArgs.HasArgument("--pin"))
            {
                //No retires allowed during cli, we dont want the device to lock out
                if (keyData.IsRetry)
                {
                    return false;
                }

                input = CliArgs.GetArgument("--pin");
            }
            //Check for environment variable
            else if (Environment.GetEnvironmentVariable(Program.YUBIKEY_PIN_ENV_VAR_NAME) != null)
            {
                //No retires allowed during env, we dont want the device to lock out
                if (keyData.IsRetry)
                {
                    return false;
                }
                input = Environment.GetEnvironmentVariable(Program.YUBIKEY_PIN_ENV_VAR_NAME);
            }
            //If the silent flag is set, a pin cli or env must be set, since we cannot write to STDOUT
            else if (CliArgs.HasArgument("--silent") || CliArgs.HasArgument("-s"))
            {
                return false;
            }
            else
            {
                Log.Information("Please enter your device pin, you have {t} attempts remaining, press enter to cancel", keyData.RetriesRemaining);

                input = Console.ReadLine();
            }

            if (string.IsNullOrWhiteSpace(input))
            {
                return false;
            }

            byte[] pinData = Encoding.UTF8.GetBytes(input);

            //Submit pin
            keyData.SubmitValue(pinData);
            return true;
        }

        private static ERRNO ConvertFromBer(Span<byte> berData)
        {
            static ReadOnlySpan<byte> GetSequence(ReadOnlySpan<byte> bytes)
            {
                //Parse the initial sequence
                AsnDecoder.ReadSequence(bytes, AsnEncodingRules.DER, out int seqStart, out int seqLen, out _, Asn1Tag.Sequence);

                //Return the discovered sequence
                return bytes.Slice(seqStart, seqLen);
            }

            //Read the initial sequence
            ReadOnlySpan<byte> seq = GetSequence(berData);

            //Reat the r integer value first
            ReadOnlySpan<byte> r = AsnDecoder.ReadIntegerBytes(seq, AsnEncodingRules.DER, out int read);

            //Get s after r
            ReadOnlySpan<byte> s = AsnDecoder.ReadIntegerBytes(seq[read..], AsnEncodingRules.DER, out _);

            int rlen = 0, slen = 0;

            //trim leading whitespace
            while (r[0] == 0x00)
            {
                r = r[1..];
            }
            while (s[0] == 0x00)
            {
                s = s[1..];
            }

            rlen = r.Length;
            slen = s.Length;

            //Concat buffer must be 2* the size of the largest value, so we can add padding
            Span<byte> concatBuffer = stackalloc byte[Math.Max(rlen, slen) * 2];

            if (rlen > slen)
            {
                //Write r first
                r.CopyTo(concatBuffer);

                //Write s to the end of the buffer, zero padding exists from stackalloc
                s.CopyTo(concatBuffer[rlen..][(rlen - slen)..]);
            }
            else if (rlen < slen)
            {
                //offset the begining of the buffer for leading r padding
                r.CopyTo(concatBuffer[(slen - rlen)..]);

                //Write s to the end of the buffer, zero padding exists from stackalloc
                s.CopyTo(concatBuffer[slen..]);
            }
            else
            {
                r.CopyTo(concatBuffer);

                s.CopyTo(concatBuffer[rlen..]);
            }

            //Write back to output buffer
            concatBuffer.CopyTo(berData);

            //Return number written
            return concatBuffer.Length;
        }

        public ERRNO ComputeSignatureFromHash(ReadOnlySpan<byte> hash, Span<byte> outputBuffer)
        {
            Log.Debug("Signing authentication data using YubiKey...");

            //Get the current jwt state as a binary buffer
            byte[] signature = _session!.Sign(PivSlot, hash.ToArray());

            //Covert from BER encoding to IEEE fixed/concat signature data for jwt
            ERRNO count = ConvertFromBer(signature);

            //Copy to output buffer
            signature[..(int)count].CopyTo(outputBuffer);

            return count;
        }
    }
}
