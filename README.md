# PKIAuthenticator (aka vauth)

*A command line tool for generating certificate-based, signed, One-Time-Passwords for web/service authentication, with YubiKey support by default*

## What is Vauth?
This repository contains source code for a .NET/8.0 command-line tool used to generate certificate-backed One-Time-Passwords (OTP) for client authentication. This method is a single (1) factor authentication based on a username (usually an email address) stored in a JsonWebToken (JWT) claim, that will be submitted to a server's PKI endpoint to authenticate your client. Extremely simple and most secure methods by default is the design goal of this tool.

### Hardware support
This tool currently uses the Yubico core sdk for using PIV enabled YubiKey devices. Since certificate based authentication is required, your YubiKey device must be PIV enabled. This is the recommended way to generate OTPs (assuming you own a YubiKey). By default the 0x9A PIV is slot is used to sign OTPs, but you my override the slot number. (see `--help` for more info) If your slot is PIN protected, you will be prompted to enter it when required, but you my also specify it as an argument **not recommended**, or via an environment variable, to inline the authentication process. (see `--help` for more info)

### Software support
This tool also supports software certificates/keys, check the usage below. This tool does not generate certificates/keys, you must use a tool such as OpenSSL to generate your certificates. Your certificate private keys must be PEM encoded x509 format, and your private key must be stored in plain text PEM, or may be encrypted PEM format. If your private key file is encrypted, you must specify the `--password` argument, this will cause a prompt for your encryption password, the `--password` flag my be followed by your plaintext password **not recommended**, or set via an environment variable. (see `--help` for more info) 

## Usage  
### OTP generation (hardware)
In hardware mode (default) by running `.\vauth.exe` will connect to the first *PIV enabled* YubiKey connected to your machine, and use it's 0x9A authentication slot to sign your newly created OTP credential. If you do not specify a username, the CN subject field is used as your `sub` field for the OTP (required for PKI authentication endpoints to know who you are). It also sets the required `keyid` field to the sha1 hash of the certificate stored in the 0x9A slot. (see `--help` for how to set a username). *Note:* the `keyid` field must match the public key id that was initially loaded under your username, otherwise the authentication will fail. 

### OTP generation (software)
`--software cert.pem --private-key key.pem`

In software mode, your x509 certificate file is loaded, along with your private key file (may be password protected). If valid, an OTP is generated and signed by your private key. Again, your certificate subject CN is used as your username if no `--username` flag is set. 

**Implementation notes**  
To make a common hardware/software abstraction, software mode only supports RSA 1024/2048, and Elliptic curves nistP256/nistP384 for signing. In RSA mode OTP use the RS256 standard of sha256 with PKS1 padding. In EC mode, uses ES256 when using nistP256, or ES384 when using nist384 curves. 

### Public Key Export 
`--export` (for JWK encoding)  
`--export pem` (for pem encoding) 

This tool only supports exporting your public key in JWK format or in PEM encoding, it does not export the entire certificate. When exporting your public key as a JWK, the kid is set to the certificate hash, and the custom `"serial":` field is set to the certificate's hex encoded serial number.  

### List devices (hardware Only)
Lists all hardware implementation devices connected to your machine. Currently only supports YubiKey devices, which prints all devices detected by the Yubico SDK regardless of their PIV support.  

Use `-h or --help` flag to print the latest command usage and flag descriptions.  

## Extended Documentation
For more information on how to build or use this tool please see the [documentation](https://www.vaughnnugent.com/resources/software/articles?tags=docs,_PkiAuthenticator)

## Builds
Executables downloads are available for Linux-x64, win-x64 and osx-x64 on my [website](https://www.vaughnnugent.com/resources/software/modules/PkiAuthenticator).

## From source
This project uses internal and external project dependencies, all via NuGet. **However,** the internal libraries are only available from my public NuGet feeds for now. You may find the debug and release feeds from my [website](https://www.vaughnnugent.com/resources/software/modules). You will only need to add those feeds (you should consider adding it anyway :smiley:)

Tools, you will need the .NET >= 6.0 sdk installed, msbuild/dotnet build tool, along with NuGet package manager installed. 

1. Git clone
2. Add my NuGet feed from my [website](https://www.vaughnnugent.com/resources/software/modules)
3. dotnet build

If you do not wish to use the NuGet feeds, you may download the assemblies from my website, and reference the assemblies, in the project file instead of their NuGet packages references. The .tar archives include all of the required dependencies. 

## Licensing
This project is licensed to you under the GNU GPL V2+. See LICENSE.txt for more information  
