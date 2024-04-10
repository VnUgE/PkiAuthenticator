/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Package: PkiAuthenticator
* File: Program.cs 
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

using VNLib.Utils.Logging;
using VNLib.Utils.Memory;

using static PkiAuthenticator.Statics;

namespace PkiAuthenticator
{
    internal sealed class Program
    {
        public const string JWK_EXPORT_TEMPLATE = "You may copy your JWK public key\n\n{pk}\n";
        public const string TOKEN_PRINT_TEMPLATE = "You may copy your authentication token \n\n{tk}\n";
        public const string YUBIKEY_PIN_ENV_VAR_NAME = "YUBIKEY_PIN";
        public const string SOFTWARE_PASSWORD_VAR_NAME = "CERT_PASSWORD";
        public const string PEM_EXPORT_TEMPLATE = "You may copy your public key\n\n{cert}\n";

        const string HELP_MESSAGE = @$"
    vauth Copyright (c) Vaughn Nugent <vnpublic@proton.me> https://www.vaughnnugent.com/resources/software

    This program comes with ABSOLUTELY NO WARRANTY. This is free software, and you are welcome to
    redistribute it under certain conditions. See the license.txt file for more details.

    Usage: vauth <flags>

    A cross-platform hardware (YubiKey) or software backed authenticator for generating short lived 
    OTPs for VNLib.Plugins.Essentials.Accounts enabled servers. This tool generates a signed Json Web 
    Token (JWT) that can be used as a single factor authentication method for accounts that have a stored
    public key. Currently the plugin requires JSON Web Keys (JWK) format for public keys. It requires
    serial numbers, key-ids, and the public key itself, x509 is not used. You may use the --export
    flag to export this public key in the required JWK format. This tool currently supports YubiKey
    as a hardware authenticator, and PEM encoded x509 certificates as a software authenticator. You 
    may use this tool to list your connected YubiKey devices, and their serial numbers.
        
    Command flags:
        
        none/default            Genereates a signed OTP (one time password) Json Web Token
                                for authentication.

        -e, --export    <pem>   Writes the public key to the screen as a JWK, or optionally
                                PEM encoded by using the 'pem' keyword following -e.

        --list-devices          Lists the device information of all connected YubiKey devices.
                                (Ignores the --key flag)

        -h, --help              Prints this help message.

    Global flags:

        -u, --user      <uid>   The user-id (or email address) to specify during for 
                                authenticating. If not specified, uses the certificates CN
                                subject value.

        --sign                  Enables entering custom data to add to the OTP before signing.
                                This allows applications to add an extra layer of authentication
                                security. If you application requires signing data, you must set
                                this flag.  

        --software <cert file>  Runs the process using a software authenticator instead of 
                                a YubiKey hardware authenticator. The cert file must be a 
                                a valid x509 certificate with the public key. You must also
                                set the private key file path.

        --private-key   <file>  The path to the private key file, may be password protected.
                                This flag is only required in software mode.

        --password <password?>  Set this flag if your private key is password protected. 
                                The password string (utf8 decoded) used to decrypt the PEM 
                                private key file. WARNING! You should avoid setting your password 
                                after this flag unless you have cli history disabled, otherwise 
                                your password may be recovered from your shell history file. This 
                                allows you to automate the authentication process. NOTE: consider 
                                setting the {SOFTWARE_PASSWORD_VAR_NAME} environment variable before 
                                starting the process instead of supplying the password as a flag.

        --key        <serial>   Allows you to specify the serial number (int32) of the exact
                                YubiKey to connect to if multiple keys are connected. (PIV must
                                be enabled on the device)

        --pin    <device pin>   Allows you to specify your device's pin as an argument. 
                                WARNING! You should avoid using this flag unless you have cli
                                history disabled, otherwise your pin may be recovered from your 
                                history file. This allows you to automate the authentication 
                                process. NOTE: consider setting the {YUBIKEY_PIN_ENV_VAR_NAME} environment 
                                variable before starting the process instead.

        --piv-slot    <slot>    The hexadecimal YubiKey PIV slot number override to use, defaults 
                                to authentication (9a) slot.
        
        -s, --silent            Silences logs, only operation output is written to STDOUT. For pin-
                                required operations, a --pin flag must be set, or set the {YUBIKEY_PIN_ENV_VAR_NAME} 
                                env variable. If an op error occurs, an exit code is returned.

        -v, --verbose           Enables verbose logging to be written to STDOUT, is overridden
                                by silent mode, and will override -d debug mode.

        -d, --debug             Enables debug logging to be written to STDOUT, is overridden by 
                                silent mode.

    Environment Variables
        {SOFTWARE_PASSWORD_VAR_NAME}    The password used to decrypt the PEM encoded private key file in software mode
        
        {YUBIKEY_PIN_ENV_VAR_NAME}      Your secret pin used for protected yubikey operations

        {MemoryUtil.SHARED_HEAP_GLOBAL_ZERO}    Force all unmanaged heap allocations to be zero filled

        {MemoryUtil.SHARED_HEAP_FILE_PATH}      Specify a custom unmanaged heap allocator DLL file path
        

    This tool was created to quickly generate short lived One-Time-Passwords (OTP) or signed
    authentication tokens (JWT) for authenticating aginst PKI endpoints, using your YubiKey's
    authentication slot (0x9a). You may use this tool to automate a login process by using the 
    -s flag and specifying a pin with --pin (not recommended!), or setting the {YUBIKEY_PIN_ENV_VAR_NAME} 
    environment variable. 

    A software, x509 certificate file backed, mode is also supported by using the --software flag.
    The certificate file must be a PEM encoded certificate. You must also specify a PEM encoded private
    key file using the --private-key flag. This file may be encrypted, and you must specify a --password 
    flag. You may wait for a prompt, set the {SOFTWARE_PASSWORD_VAR_NAME} environment variable, or write it after 
    the --password argument: '--password my_unsecure_password'.

    Examples:
        
        OTP:
            vauth.exe                       # default cert CN usename
            vauth.exe -u 'name@example.com' # specify username
            vauth.exe --key 1111111         # specify hardware key serial numer
            vauth.exe -s > token.txt        # write token to a text file w/ silent mode
            vauth.exe --piv-slot 9C         # specify a differnt PIV slot on the yubikey (in hex)
            
            #software mode
            vauth.exe --software 'cert.pem' --private-key 'priv.pem'
            vauth.exe --software 'cert.pem' --private-key 'priv.pem' --password 'mypassword'
    
        Export public key:
            vauth.exe --export              # for JWK output
            vauth.exe --export pem          # for pem encoding

            #software
            vauth.exe --software cert.pem --export pem

        Sign data:
            vauth.exe --sign                # sign data before generating OTP

        List devices:
            vauth.exe --list-devices        # only supported in hardware mode
";

        static int Main(string[] args)
        {
            if (CliArgs.HasArgument("-h") || CliArgs.HasArgument("--help"))
            {
                Console.WriteLine(HELP_MESSAGE);
                return 0;
            }

            Log.Information("vauth © 2024 Vaughn Nugent");

            int exitCode = 1;
            try
            {
                //Get software or hardware authenticator
                using IAuthenticator authenticator = CliArgs.HasArgument("--software") ? new SoftwareAuthenticator() : new HardwareAuthenticator();

                //initialze the authenticator
                if (authenticator.Initialize())
                {
                    //Only continue if authenticator successfully initialized
                    if (CliArgs.HasArgument("--list-devices"))
                    {
                        Log.Verbose("Gathering device information");

                        //List devices flag
                        exitCode = authenticator.ListDevices();
                    }
                    else if (CliArgs.HasArgument("-e") || CliArgs.HasArgument("--export"))
                    {
                        Log.Verbose("Exporting public key");

                        //Check for pem encoding flag
                        if (CliArgs.HasArgument("pem"))
                        {
                            string pem = authenticator.ExportPem();
                            Log.Information(PEM_EXPORT_TEMPLATE, pem);
                            exitCode = 0;
                        }
                        else
                        {
                            //Print jwk
                            string? pupKey = authenticator.ExportJwk();

                            //May be null if the alg is not supported
                            if (pupKey == null)
                            {
                                Log.Error("The certificate does not use a supported algorithm");
                            }
                            else
                            {
                                //Print
                                Log.Information(JWK_EXPORT_TEMPLATE, pupKey);
                                exitCode = 0;
                            }
                        }
                    }
                    else
                    {
                        //Authenticate
                        exitCode = authenticator.GenerateOtp();
                    }
                }
            }
            catch(Exception ex)
            {
                if (Log.IsEnabled(LogLevel.Debug))
                {
                    Log.Error(ex);
                }
                else
                {
                    Log.Error("Operation failed. Reason: {ex}", ex.Message);
                }
            }

            Log.Verbose("Exiting...");

            return exitCode;
        }
    }
}