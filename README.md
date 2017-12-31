# Create OpenVPN Client Profiles
This small utility creates OpenVPN client profiles that can be easily deployed to to clients or users.  Given a client profiles with directives pointing to external files, like private keys and certificates, it will create one bundled file by adding these files as inline arguments in the client profile.

An extra feature is the possibility to transform the client profile into an iOS .mobileconfig file, which can be directly imported by any iOS device. This approach has the advantage that the client certificate and private key from the iOS Keychain are stored in the iOS Keychain, which is significantly more secure. In addition, it allows the creation of **VPN On Demand** profiles. 

### Building and Installing

Make sure you have the build prerequisites:

* `GCC`  (compiler)
* `autoconf` (build tools)
* `libssl-dev` (openssl development libraries)
* `uuid-dev` (uuid library)

Then set up the build environment:

```shell
./autogen.sh
```

Build and install:

```
./configure
make install
```

**openvpn-bundle** will be built into `src` and installed into `/usr/local/bin`

### Usage - OVPN Profile

Command line is as follows:

`openvpn-bundle --input=infile  --output=outfile`

If either `infile` or `outfile` are not supplied, standard input or output will be used.  The input must be valid OpenVPN client configuration, typically stored in a `.ovpn` file. The program will do a number of consistency checks for its own purpose and exit with an error message if it finds inconsistencies.

### Usage - Mobile Config File

To produce an iOS mobile configuration file, use the following command line:
`openvpn-bundle --input=infile  --output=outfile  --mobile-prof=profile-input`

The first two options are handled as in the basic use case, the profile-input parameter should point to a file with the following layout (comments are preceded by '#'):

```
##########################
#   Profile Parameters   #
##########################

# Apple references retrieved from : https://developer.apple.com/library/content/featuredarticles/iPhoneConfigurationProfileRef/Introduction/Introduction.html

# Profile Description - Optional
# Apple comment: A description of the profile, shown on the Detail screen for the profile. This
#                should be descriptive enough to help the user decide whether to install the
#                profile.
ProfileDescription = Profile Description

# Profile Identifier - Mandatory
# Apple comment: A reverse-DNS style identifier (com.example.myprofile, for example) that
#                identifies the profile. This string is used to determine whether a new profile
#                should replace an existing one or should be added.
Identifier = com.example.myprofile

# Name of profile - Mandatory
# Apple comment: A human-readable name for the profile. This value is displayed on the Detail
#                screen. It does not have to be unique.
Name = OpenVPN VPN OD Profile

# Organisation Issuing the profile - Optional
# Apple comment: A human-readable string containing the name of the organization that provided
#                the profile.
Organization = United Nations

##########################
#     VPN Parameters     #
##########################

# Name of the VPN connection - Mandatory
# Apple comment:  Description of the VPN connection displayed on the device.
VPNName = VPN Name

# Description of the VPN connection - Optional
# Apple comment: A human-readable description of the VPN. This description is shown on the
#                Detail screen.
VPNDescription = VPN Description

# List of SSIDs that DO NOT ACTIVATE the VPN. Seperate different values with commas
# Comment out to disable VPN On Demand.
# Put key with empty value to trust no SSID, ie activate VPN for all WiFi
AllowedSSIDS 

##########################
# Certificate Parameters #
##########################

# Name of the PKCS12 Certificate - Mandatory
# Apple comment:  Description of the Certificate displayed on the device.
CertificateName = VPN OD Certficate

# Description of Certificate - Optional
# Apple comment: A human-readable description of the Certificate. This description is shown on
#                the Detail screen.
CertificateDescription = Certificate description

# Password to protect certificate - Optional
# User will be prompted for this password when installing the certificate on the iOS device.
# If no password is provided in the input file, openvpn-bundle will prompt the user to enter
# one, if possible.
# If that is not possible (because input/output are redirected), an error will occur.
# To use a blank password, add the key without a value.
Password = !Vgbj7Po0)

```

Update this file with values appropriate for your setup and run as shown above. The program will do a number of consistency checks for its own purpose and exit with an error message if it finds inconsistencies. If all goes well, it will produce an xml file, in `outfile ` or on `stdout`. This file typically has a `.mobileconfig` extension and can be distributed by email or, if you're on a Mac, with the **iPhone Configuration Utility**.

### VPN On Demand Configuration

**openvpn-bundle** supports a limited implementation of iOS VOD profiles. iOS VOD will automatically set up a VPN tunnel when certain criteria or met. The implementation done here is a simple "distrust wireless" setup. It is activated by adding the `AllowedSSIDS` key to the configuration input. The meaning of this key is *"distrust all wireless networks except the ones listed here"*. Putting this key without any value instructs iOS to activate the VPN tunnel as soon as your iOS device starts using WiFi. Adding a list of networks like `AllowedSSIDS = MyHomeWiFi,CorporateWiFi`will instruct iOS to set up a VPN tunnel when your device is connected to any WiFi except 'MyHomeWiFi' or 'CorporateWiFi'.

As explained [here](https://developer.apple.com/library/content/featuredarticles/iPhoneConfigurationProfileRef/Introduction/Introduction.html#//apple_ref/doc/uid/TP40010206-CH1-SW36), iOS supports other types of rules for activating V.O.D. For the moment these are not implemented in openvpn-bundle, but since the program's out is an xml file, you can manually edit that file to implement