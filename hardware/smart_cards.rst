Smart cards
===========

Acronyms
--------

Generic acronyms (used for something else than smart cards):

:3GPP: Third Generation Partnership Project
:AES: Advanced Encryption Standard (symmetric encryption algorithm)
:ANSI: American National Standards Institute
:ASN.1: Abstract Syntax Notation One (defined in X.680)
:BER: Basic Encoding Rules (defined in X.690 from ITU-T)
:CBC: Cipher-Block Chaining mode (defined in FIPS PUB 81)
:CFB: Cipher-Feedback Mode
:CMAC: Cipher-based Message Authentication Code
:CRC: Cyclic Redundancy Code (a 2-byte checksum, ISO/IEC 13239)
:DER: Distinguished Encoding Rules (defined in X.690 from ITU-T)
:DES: Data Encryption Standard (FIPS PUB 46-3)
:DSA: Digital Signature Algorithm (FIPS PUB 186-4)
:ECB: Electronic Codebook mode (defined in FIPS PUB 81)
:ECDH: Elliptic Curve Diffie Hellman
:ECDSA: Elliptic Curve Digital Signature Algorithm (asymmetric signature/authentication algorithm)
:EMV: Europay Mastercard Visa
:ETSI: European Telecommunications Standards Institute
:FIPS: Federal Information Processing Standard
:GPG: GNU Privacy Guard
:ICC: Integrated Circuit Card (= smart card)
:ICCD: Integrated Circuit Card Device
:IEC: International Electrotechnical Commission
:ISO: International Organization for Standardization
:ITU: International Telecommunication Union
:ITU-T: ITU Telecommunication Standardization Sector
:IV: Initialization Vector
:LRC: Longitudinal Redundancy Code (a 1-byte checksum by XOR)
:MAC: Message Authentication Code
:MIME: Multipurpose Internet Mail Extensions
:NDEF: NFC Forum Data Exchange Format
:NFC: Near-field Communication (ISO/IEC 18092)
:NIST: National Institute of Standards and Technology
:OID: Object Identifier
:OMAC: One-key MAC (OMAC1 = CMAC, OMAC2 = evolution)
:PGP: Pretty Good Privacy
:PII: Personally Identifiable Information
:PIN code: Personal Identity Number
:PKCS: Public Key Cryptography Standards
:PRF: Pseudo random function
:PUK code: Personal Unlocking Key
:RFID: Radio-Frequency Identification
:RSA: Rivest-Shamir-Adleman (asymmetric encryption and signature/authentication algorithm defined in PKCS#1)
:S/MIME: Secure/Multipurpose Internet Mail Extensions
:SPI: Serial Peripheral Interface
:TDEA: Triple Data Encryption Algorithm, Triple DES (3DES)
:USB: Universal Serial Bus
:UTF-8: Universal Character Set (UCS) Transformation Format
:UUID: Universally Unique IDentifier

Acronyms specific to the domain of smart cards:

:AC: Access Condition (access restrictions to the smart card filesystem)
:ACD: Application Capability Description (ISO/IEC 7816-15)
:AID: Application Identifier (defined in ISO/IEC 7816-5, two elements: RID = registered 5-byte identifier, PIX = proprietary application identifier extension)
:APDU: Application Protocol Data Unit (communication unit between a smart card reader and a smart card)
:ASIC: Application Specific Integrated Circuit (similar to ASSP)
:ASSP: Application Specific Standard Part
:ATR: Answer To Reset (first received data after reset, which can be used to identify a smart card reader)
:CAD: Card Acceptance Device (= smart card reader)
:CCD: Card Capability Description (ISO/IEC 7816-15)
:CCID: Chip/Smart Card Interface Device (protocol over USB)
:CCV: Cryptographic Check Value (like a CMAC)
:CHUID: Card Holder Unique Identifier
:CHV: Card Holder Verification (like a PIN code)
:CIA: Cryptographic Information Application (ISO/IEC 7816-15)
:DDO: Discretionary ASN.1 Data Object
:DF: Dedicated File (directory of the filesystem)
:DO: Data Object
:DSI: Data Structures for Interoperability (ISO/IEC 24727-3)
:EF: Elementary File (can be Working EF or Internal EF)
:FCI: File Control Information
:FCP: File Control Parameters
:FID: File Identifier (2 bytes in ISO/IEC 7816-4, short FID is 5-bit long)
:FMD: File Management Data
:IFD: Interface Device (= smart card reader)
:KUC: Key Usage Counters
:MF: Master File (root directory of the filesystem, its FID is ``3F00``)
:PC/SC: Personal Computer/Smart Card (specification for smart-card integration into computing environments)
:PCD: Proximity Coupling Device (eg. NXP MFRC522 Contactless Reader IC)
:PICC: Proximity Integrated Circuit Card (a card or tag using the ISO 14443A interface, eg. Mifare or NTAG203)
:PIV: Personal Identity Verification (USA FIPS 201)
:PSO: Perform Security Operation
:PSO AUT: Perform Security Operation: Authenticate
:PSO CDS: Perform Security Operation: Compute Digital Signature
:PSO DEC: Perform Security Operation: Decipher
:SAM: Secure Access Modules
:SCP: Secure Channel Protocol (GlobalPlatform specification, SCP02 = 3DES-CBC encrypt-and-MAC, SCP03 = AES-CBC encrypt-then-MAC)
:SE: Security Environment
:SIM: Subscriber Identity Module (ETSI and 3GPP)
:SM: Secure Messaging
:SO: Security Officer user
:TPDU: Transmission Protocol Data Unit (transmission of an APDU by T=0)


Standards
---------

* ISO/IEC 7816: Identification cards - Integrated circuit cards:

  * ISO/IEC 7816-1: Cards with contacts - Physical characteristics
  * ISO/IEC 7816-2: Cards with contacts - Dimensions and location of the contacts
  * ISO/IEC 7816-3: Cards with contacts - Electrical interface and transmission protocols

    - Define transmission mode, ATR, etc.

  * ISO/IEC 7816-4: Organization, security and commands for interchange

    - Define APDUs, EF, DF, etc.
    - Accessible online at http://cardwerk.com/smart-card-standard-iso7816-4-section-6-basic-interindustry-commands/

  * ISO/IEC 7816-5: Registration of application providers
  * ISO/IEC 7816-6: Interindustry data elements for interchange
  * ISO/IEC 7816-7: Interindustry commands for Structured Card Query Language (SCQL)
  * ISO/IEC 7816-8: Commands and mechanisms for security operations
  * ISO/IEC 7816-9: Commands for card management
  * ISO/IEC 7816-10: Electronic signals and answer to reset for synchronous cards
  * ISO/IEC 7816-11: Personal verification through biometric methods
  * ISO/IEC 7816-12: Cards with contacts - USB electrical interface and operating procedures
  * ISO/IEC 7816-13: Commands for application management in a multi-application environment
  * ISO/IEC 7816-15: Cryptographic information application

    - Defines some DF specific to cryptographic operations ("GET DATA 7F62" for CCD, EF.CIAInfo (5032), EF.OD (5031))

* ISO/IEC 14443: Identification cards - Contactless integrated circuit cards - Proximity cards

  - Defines Type A and Type B cards (PICC), used by NFC Type 4 Tag
  - Communication via radio at 13.56 MHz (RFID HF)

* ISO/IEC 18092: Information technology - Telecommunications and information exchange between systems - Near Field Communication - Interface and Protocol (NFCIP-1)

* ETSI EN 726 / ETSI TS 101 206-3
  https://www.etsi.org/deliver/etsi_ts/101200_101299/10120603/01.03.02_60/ts_10120603v010302p.pdf

* FIPS 201: Personal Identity Verification (PIV) of Federal Employees and Contractors
  https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.201-2.pdf
  OID 2.16.840.1.101.3.6...
  Implementation in Apple: https://opensource.apple.com/source/Tokend/Tokend-37563/PIV/PIVDefines.h

* PKCS (RSA Security Inc):

  * PKCS#1 RSA Cryptography Standard
    https://tools.ietf.org/html/rfc3447
  * PKCS#11 Cryptographic Token Interface ("Cryptoki")
    http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html
  * PKCS#15 Cryptographic Token Information Format Standard
    https://www.usenix.org/legacy/events/smartcard99/full_papers/nystrom/nystrom.pdf
    Defines ``DF(PKCS15)``:

    * ODF: Object Directory File (EF, record-oriented structure)
    * PrKDFs (DF for private keys)
    * PuKDFs (DF for public keys)
    * SKDFs (DF for secret/symmetric keys)
    * CDFs: Certificate Directory Files
    * DODFs: Data Object Directory Files
    * AODFs: Authentication Object Directory Files

* Functional Specification of the OpenPGP application on ISO Smart Card Operating Systems
  https://www.g10code.com/docs/openpgp-card-3.0.pdf

Software
--------

* OpenSC, Open source smart card tools and middleware. PKCS#11/MiniDriver/Tokend
  https://github.com/OpenSC/OpenSC
* CCID driver of pcsclite
  https://github.com/LudovicRousseau/CCID

Stacking:

* Web browser (for HTTPS authentication) -> PKCS#11 plugin -> ``/usr/lib/pkcs11/opensc-pkcs11.so`` -> OpenSC (``libopensc.so``) -> PC/SC Daemon (``pcscd``) -> CCID driver -> USB -> Smart Card
* ``opensc-tool``, ``pkcs11-tool``, ``pkcs15-tool``, ``openpgp-tool`` -> OpenSC -> PC/SC Daemon -> ...
* ``pcsc_scan -n``, Python ``pyscard`` -> PC/SC Lite (``libpcsclite.so``) -> PC/SC Daemon -> ...
* ``gpg``, ``ssh`` -> GnuPG Agent -> Smart Card Daemon (``scdaemon``) -> GnuPG CCID Driver -> USB -> Smart Card

  - with ``--disable-ccid`` and ``--pcsc-driver=/usr/lib/libpcsclite.so`` in ``scdaemon``: ``scdaemon`` -> PC/SC Lite -> PC/SC Daemon -> ...

OpenSC identifies cards according to their ATR and select drivers such as ``piv`` or ``openpgp``.

PS/SC Daemon listens on a Unix socket, on Unix-based systems, on ``/run/pcscd/pcscd.comm``. It can log APDUs.

The USB-CCID driver used by PC/SC Daemon is present in ``/usr/lib/pcsc/drivers/ifd-ccid.bundle/Contents/Linux/libccid.so`` and uses ``libusb`` to communication to USB devices through ``/dev/bus/usb/...``.


Some commands:

* Search smart card readers::

    pcsc_scan -n

* Dump information about PKCS#15 interface::

    # Get information about private keys
    pkcs15-tool -k
    # Dump data objects
    pkcs15-tool -D
    pkcs11-tools --list-objects

* Show information about an OpenPGP smart card::

    openpgp-tool -U

* Read the PIV certificate using PKCS#15 interface::

    pkcs15-tool --read-certificate 01 --output piv_certificate.crt
    openssl x509 -noout -text -in piv_certificate.crt

    # Encrypt data using it
    openssl rsautl -encrypt -raw -certin -inkey piv_certificate.crt -in message -out encrypted-message.bin
    # Decrypt using the smart card
    pkcs11-tool -v --decrypt -i encrypted-message.bin -o decrypted-message


Connection
----------

A smart card component (chipset, USB key, physical card like a SIM card...) can use several buses for connections between a card and a reader and between a reader and a host/client:

* USB (usually with CCID protocol)
* SPI Serial Interface
* I²C (Two Wire Interface)

ISO/IEC 7816-3 defines several types of transmission (found in 4 bits ``T`` in the Answer to Reset, ATR), the first two are in general use:

* ``T=0``: half duplex transmission of characters
* ``T=1``: half duplex transmission of blocks
* ``T=2/3``: reserved for full duplex operation
* ``T=4``: reserved for enhanced half duplex byte transmission
* ``T=5-13``: reserved for further use (RFU)
* ``T=14``: non ISO protocols
* ``T=15``: reserved for future extension

Filesystem
----------

A smart card may have an internal filesystem which is used in commands. Files are selected using ``SELECT FILE`` command.

* The root directory is the MF (Master File), identified by FID ``3F00``.
* Directories (DF, Dedicated File) may have FID ``7Fxx``
* Files (EF, Elementary File) in the MF may have FID ``2Fxx``, otherwise ``6Fxx``
* FID ``FFFF`` is reserved for future use (ISO/IEC 7816-4)
* EF ``2F00`` (named "``EF DIR``") store application identifiers along with the path name for the association applications (ISO/IEC 7816-4).
  ETSI TS 101 206-3 defines it as:

    ``EF DIR`` is an elementary file at the MF or at DF level, which contains a list of all, or part of, available applications in the card (see also ISO 7816-5)

* EF ``2F01`` (named "``EF ATR``") contains the extension to the ATR (ISO/IEC 7816-4)

EF can be of several types:

* transparent structure
* linear structure with records of fixed size
* linear structure with records of variable size
* cyclic structure with records of fixed size
* TLV structure (with Data Objects, DOs, accessible with GET DATA/PUT DATA commands)

"read/update binary" is possible only for transparent EF. The other ones can be used with "read/create/update record"


Examples of Application Identifiers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

On Yubikey 4:

* ``A0 00 00 03 08``: PIV
* ``A0 00 00 05 27 10 02``: Old U2F
* ``A0 00 00 05 27 20 01``: OTP
* ``A0 00 00 05 27 21 01``: OATH
* ``A0 00 00 05 27 47 11 17``: MGR (Yubikey Manager)
* ``D2 76 00 01 24 01 02 01 00 06 xx xx xx xx 00 00``: OpenPGP 2.1 by Yubico


OpenPGP application data structure
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* AID :

  * RID from FSF Europe e.V.: ``D2 76 00 01 24``
  * PIX: application ``01``, version ``xx xx``, manufacturer ``xx xx``, serial number ``xx xx xx xx``, reserved for future use ``00 00``

* There may be MF (``3F00``), EF.DIR (``2F00``), EF.ATR/INFO (``2F01``) at the root

  * EF.DIR may declare the application with tag ``4F`` (AID) "``D27600012401``" and tag ``50`` (application label) "OpenPGP" with the following record (command "GET DATA")::

      61 11 4F 06 D27600012401 50 07 4F70656E504750

    In order to read all the data, this APDU can be used: ``00CB 2F00 02 5C00 00``

* DF.OpenPGP is selected by AID and contains these DO (Data Objects):

  * ``4D`` (PUT DATA only) Extended Header list, used for optional key import (``7F48``: Cardholder private key template, ``5F48``: Cardholder private key)
  * ``4F`` (GET DATA only) AID
  * ``5B`` Cardholder name
  * ``5E`` Login data
  * ``65`` (GET DATA) Cardholder-related data
  * ``6E`` (GET DATA) Application-related data
  * ``73`` (GET DATA) Discretionary data objects
  * ``7A`` (GET DATA) Security support template
  * ``93`` (GET DATA) Digital signature counter
  * ``C1`` Algorithm attributes signature
  * ``C2`` Algorithm attributes decryption
  * ``C3`` Algorithm attributes authentication
  * ``C4`` PW status Bytes
  * ``C5`` (GET DATA) Fingerprints
  * ``C6`` (GET DATA) List of CA-Fingerprints
  * ``C7`` (PUT DATA) Fingerprint (binary) for signature key
  * ``C8`` (PUT DATA) Fingerprint (binary) for decryption key
  * ``C9`` (PUT DATA) Fingerprint (binary) for authentication key
  * ``CA``-``CC`` (PUT DATA) 3 CA-Fingerprints (binary)
  * ``CD`` (GET DATA) List of generation dates/times of public key pairs
  * ``CE`` (PUT DATA) Generation date/time of signature key
  * ``CF`` (PUT DATA) Generation date/time of decryption key
  * ``D0`` (PUT DATA) Generation date/time of authentication key
  * ``D1`` (PUT DATA) Optional DO for SM (SM-Key-ENC)
  * ``D2`` (PUT DATA) Optional DO for SM (SM-Key-MAC)
  * ``D3`` (PUT DATA) Resetting Code
  * ``D5`` (PUT DATA) Optional DO for PSO:DEC
  * ``D6`` User Interaction Flag (UIF) for PSO:CDS (ie. "touch policy" when there is a button)
  * ``D7`` User Interaction Flag (UIF) for PSO:DEC
  * ``D8`` User Interaction Flag (UIF) for PSO:AUT
  * ``F4`` (PUT DATA) Optional DO for SM (Container for both SM keys (ENC and MAC) with Tags ``D1`` and ``D2``
  * ``010x`` private use (optional)
  * ``5F2D`` Language preferences
  * ``5F35`` Sex
  * ``5F50`` URL
  * ``5F52`` (GET DATA) Historical bytes
  * ``7F21`` Cardholder certificates (AUT, DEC, SIG)
  * ``7F66`` (GET DATA) Extended length information (defines the maximum number of bytes in a command APDU and a response APDU)
  * ``7F70`` (GET DATA) Virtual root
  * ``7F74`` (GET DATA) General feature management (display, LED, buttons or fingerprint sensors)

Useful commands:

* Get the serial number (AID)::

    gpg-connect-agent 'SCD SERIALNO openpgp' /bye

* Retrieve the ID of the OpenPGP key::

    gpg --card-status --keyid-format 0xlong

* Cryptographic operations::

    gpg --armor --encrypt --recipient="$KEYID" --output encrypted.asc message
    gpg --decrypt --output decrypted-message encrypted.asc

    gpg --armor --sign --detach-sign --default-key="$KEYID" --output signature.asc message
    gpg --verify signature.asc message


Smart card instructions
-----------------------

Commands to smart cards are formatted as APDUs. A command (request) contains the following components (ISO/IEC 7816-4):

* ``CLA`` (1 byte): instruction class
* ``INS`` (1 bytes): instruction code
* ``P1``, ``P2`` (1 bytes each): parameters
* ``Lc`` (0, 1 or 3 bytes): number of bytes of command data (``Nc``). If ``Lc`` is 3-bytes wide, the first one must be 0.
* Command data (``Nc`` bytes)
* ``Le`` (0, 1, 2 or 3 bytes): maximum number of response bytes expected (``Ne``)

The response data contains at most ``Ne`` bytes (its size is ``Nr`` bytes) and is followed by a 2-byte status word (``SW1-SW2``).

A 5-byte header is used to transmit the command (as a TPDU), ``[CLA, INS, P1, P2, P3]``, where ``P3`` encodes the number of data bytes to be transferred during the command.

ISO/IEC 7816-3 defines 4 cases of APDU:

* case 1: ``Nc = 0, Nr = 0`` (no command data nor response data), there are only the header and the status word (no ``Lc``/``Le``).
* case 2: ``Nc = 0, Nr != 0`` (no command data but there is response data), ``Lc`` is absent but ``Le`` is present.

  - case 2S ("short"): 1-byte ``Le``, ``00`` meaning 256.
  - case 2E ("extended"): 3-byte ``Le``, its first byte being ``00``. ``000000`` means the maximum, 65536.

* case 3: ``Nc != 0, Nr = 0`` (command data and no response data), ``Le`` is absent but ``Lc`` and command data are in the command.

  - case 3S: 1-byte ``Lc``, not zero (encodes from 1 to 255)
  - case 3E: 3-byte ``Lc``, ``00xxxx`` with ``xxxx`` not zero (encodes from 1 to 65535)

* case 4: ``Nc != 0, Nr != 0`` (command data and response data), there are all fields.

  - case 4S: 2S and 3S
  - case 4E: 3E and 2-byte ``Le`` to be read like 2E (there is no duplicated null byte)

When a smart card received an APDU, known its size, it can determine which case applies according to the value of the 5th byte.

Encapsulating APDUs/TPDUs over USB using CCID standard is described in the CCID specification: http://www.usb.org/developers/docs/devclass_docs/DWG_Smart-Card_CCID_Rev110.pdf

APDU Command Class
~~~~~~~~~~~~~~~~~~

* Bit 8: 0 means "interindustry class" (``0x00-0x7f``)

  * ``CLA`` = ``000. ....`` (``0x00-0x1f``): First interindustry values of CLA

    * bit 5 (``0x10``): Command chaining control (0 if last or only command of a chain)
    * bits 3-4 (``0x0c``): Secure messaging indication:

      * ``0x00`` no SM
      * ``0x04`` Proprietary SM format
      * ``0x08`` SM according to ISO/IEC 7816-4 without header authentication
      * ``0x0c`` SM according to ISO/IEC 7816-4 with header authentication

    * bits 1-2 (``0x03``): Logical channel number, between 0 and 3

  * ``CLA`` = ``01.. ....`` (``0x40-0x7f``): Further interindustry values of CLA

    * bit 6 (``0x20``): Secure messaging indication (``0x00`` no SM, ``0x20`` SM according to ISO/IEC 7816-4 without header authentication)
    * bit 5 (``0x10``): Command chaining control (0 if last or only command of a chain)
    * bits 1-4 (``0x0f``): Logical channel number, between 4 and 19 (the value is added with 4)

* Bit 8: 1 means "proprietary class" (``0x80-0xfe``)

  * ``CLA=0xff``: invalid



APDU Command Instructions
~~~~~~~~~~~~~~~~~~~~~~~~~

Here is a table listing known instruction code for several standards.

Source: http://techmeonline.com/most-used-smart-card-commands-apdu/

+--------------+----------------------------------------+-----------------+------------------------------------------------------+
| Instruction  | Command                                | Standard        | Function                                             |
| ``INS``      |                                        |                 |                                                      |
| [``P1P2``]   |                                        |                 |                                                      |
+==============+========================================+=================+======================================================+
|   ``0x04``   | DEACTIVATE FILE                        | ISO/IEC 7816-9  | Reversibly block a file.                             |
|              +----------------------------------------+-----------------+------------------------------------------------------+
|              | INVALIDATE                             | TS 51.011,      | Reversibly block a file.                             |
|              |                                        | EN 726-3        |                                                      |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0x0C``   | ERASE RECORD(S)                        | ISO/IEC 7816-4  | Erase a record in a record-oriented file.            |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0x0E``   | ERASE BINARY                           | ISO/IEC 7816-4  | Set the content of a file with a transparent         |
+--------------+                                        |                 | structure to the erased state.                       |
|   ``0x0F``   |                                        |                 |                                                      |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0x10``   | PERFORM SCQL OPERATION                 | ISO/IEC 7816-7  | Execute an SCQL instruction.                         |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0x12``   | PERFORM TRANSACTION OPERATION          | ISO/IEC 7816-7  | Execute an SCQL transaction instruction.             |
|              |                                        |                 | (``P1=00``, ``P2=81/82/83`` for                      |
|              |                                        |                 | BEGIN/COMMIT/ROLLBACK)                               |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0x14``   | PERFORM USER OPERATION                 | ISO/IEC 7816-7  | Manage users in the context of SCQL.                 |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0x18``   | APPLICATION UNBLOCK                    | EMV             | Unblock an application.                              |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0x1E``   | APPLICATION BLOCK                      | EMV             | Reversibly block an application.                     |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0x20``   | VERIFY                                 | ISO/IEC 7816-4, | Verify the transferred data (such as a PIN)          |
|              |                                        | EMV             | (``P1=00``, ``P2=81/82/83`` for PW1/2/3).            |
|              |                                        | OpenPGP         |                                                      |
|              +----------------------------------------+-----------------+------------------------------------------------------+
|              | VERIFY CHV                             | TS 51.011       | Verify the PIN.                                      |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0x21``   | VERIFY                                 | ISO/IEC 7816-4  | Verify the transferred data.                         |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0x22``   | MANAGE SECURITY ENVIRONMENT (MSE)      | ISO/IEC 7816-8  | Change the parameters for using cryptographic        |
|              |                                        |                 | algorithms in the smart card.                        |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0x24``   | CHANGE CHV                             | TS 51.011       | Change the PIN.                                      |
|              +----------------------------------------+-----------------+------------------------------------------------------+
|              | CHANGE REFERENCE DATA                  | ISO/IEC 7816-8  | Change the data used for user identification         |
|              |                                        | OpenPGP         | (e.g. a PIN, ``P1=00``, ``P2=81/83`` for PW1/2).     |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0x26``   | DISABLE CHV                            | TS 51.011       | Disable PIN queries.                                 |
|              +----------------------------------------+-----------------+------------------------------------------------------+
|              | DISABLE VERIFICATION REQUIREMENT       | ISO/IEC 7816-8  | Disable user identification (e.g., PIN queries).     |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0x28``   | ENABLE CHV                             | TS 51.011,      | Enable PIN queries.                                  |
|              |                                        | EN 726-3        |                                                      |
|              +----------------------------------------+-----------------+------------------------------------------------------+
|              | ENABLE VERIFICATION REQUIREMENT        | ISO/IEC 7816-8  | Enable user identification (e.g., PIN queries).      |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0x2A``   | PERFORM SECURITY OPERATION (PSO)       | ISO/IEC 7816-8  | Execute a cryptographic algorithm in the smart card. |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
| ``2A 9E 9A`` | COMPUTE DIGITAL SIGNATURE (PSO:CDS)    | OpenPGP         | Sign the command data.                               |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
| ``2A 80 86`` | DECIPHER (PSO:DEC)                     | OpenPGP         | Decipher the command data (with padding indicator    |
|              |                                        |                 | byte ``00`` or ``02``).                              |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0x2C``   | RESET RETRY COUNTER                    | ISO/IEC 7816-8  | Reset an error counter.                              |
|              |                                        | OpenPGP         | (``P1=00/02``, ``P2=81`` for PW1)                    |
|              +----------------------------------------+-----------------+------------------------------------------------------+
|              | UNBLOCK CHV                            | TS 51.011 EN    | Reset a PIN retry counter that has reached its       |
|              |                                        |                 | maximum value.                                       |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0x30``   | DECREASE                               | EN 726-3        | Reduce the value of a counter in a file.             |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0x32``   | INCREASE                               | TS 51.011       | Increase the value of a counter in a file.           |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0x34``   | DECREASE STAMPED                       | EN 726-3        | Reduce the value of a counter in a file that is      |
|              |                                        |                 | protected using a cryptographic checksum.            |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0x36``   | INCREASE STAMPED                       | EN 726-3        | Increase the value of a counter in a file that       |
|              |                                        |                 | is protected using a cryptographic checksum.         |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0x44``   | ACTIVATE FILE                          | ISO/IEC 7816-9  | Reversibly unblock a file.                           |
|              |                                        | OpenPGP         | (``P1P2=0000``)                                      |
|              +----------------------------------------+-----------------+------------------------------------------------------+
|              | REACTIVATE FILE                        | ISO/IEC 7816-9  | Unblock a file.                                      |
|              +----------------------------------------+-----------------+------------------------------------------------------+
|              | REHABILITATE                           | TS 51.011 EN ???| Unblock a file.                                      |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0x46``   | GENERATE PUBLIC KEY PAIR               | ISO/IEC 7816-8  | Generate a key pair for an asymmetric cryptographic  |
|              +----------------------------------------+-----------------+ algorithm.                                           |
|              | GENERATE ASYMMETRIC KEY PAIR           | ISO/IEC 7816-4  |                                                      |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0x47``   | GENERATE PUBLIC KEY PAIR               | OpenPGP         | ``P1P2=8000``: Generate an internal private key      |
|              |                                        |                 | ``P1P2=8100``: Read the actual public key template   |
|              |                                        |                 | (i.e. get the public key)                            |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0x50``   | INITIALIZE IEP                         | EN 1546-3       | Initialize IEP for a subsequent purse command.       |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0x52``   | CREDIT IEP                             | EN 1546-3       | Load the purse (IEP).                                |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0x54``   | DEBIT IEP                              | EN 1546-3       | Pay from the purse                                   |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0x56``   | CONVERT IEP CURRENCY                   | EN 1546-3       | Convert currency.                                    |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0x58``   | UPDATE IEP PARAMETER                   | EN 1546-3       | Change the general parameters of a purse.            |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0x5A``   | GET PREVIOUS IEP SIGNATURE             | EN 1546-3       | Repeat the computation and output of the last        |
|              |                                        |                 | signature received IEP.                              |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|``0x60-0x6f`` | (invalid)                              | ISO/IEC 7816-4  | This allows the card to acknowledge with ``SW1=INS``.|
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0x70``   | INITIALIZE PSAM                        | EN 1546-3       | Initialize PSAM for a subsequent purse command.      |
|              +----------------------------------------+-----------------+------------------------------------------------------+
|              | MANAGE CHANNEL                         | ISO/IEC 7816-4  |                                                      |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0x72``   | CREDIT PSAM                            | EN 1546-3       | Pay from IEP to the PSAM.                            |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0x74``   | PSAM COMPLETE                          | EN 1546-3       | End paying the IEP against the PSAM.                 |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0x76``   | INITIALIZE PSAM for Online Collection  | EN 1546-3       | Initialize PSAM for online booking of the amount.    |
|              +----------------------------------------+-----------------+------------------------------------------------------+
|              | LOCK                                   | EN 726-3        | Set to Never the AC of one or several specific       |
|              |                                        |                 | groups of functions with the same AC requirements    |
|              |                                        |                 | of the current selected file.                        |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0x78``   | PSAM COLLECT                           | EN 1546-3       | Execute PSAM online booking of an amount.            |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0x7A``   | PSAM COLLECT                           | EN 1546-3       | End PSAM online booking of an amount.                |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0x7C``   | INITIALIZE PSAM for Offline Collection | EN 1546-3       | Initialize PSAM for offline booking of the amount.   |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0x7E``   | PSAM VERIFY COLLECTION                 | EN 1546-3       | End PSAM offline booking of an amount.               |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0x80``   | INITIALIZE PSAM for Update             | EN 1546-3       | Initialize PSAM for changing the parameters.         |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0x82``   | EXTERNAL AUTHENTICATE                  | ISO/IEC 7816-4  | Authenticate the outside world with respect to the   |
|              |                                        |                 | smart card (by responding to a challenge).           |
|              +----------------------------------------+-----------------+------------------------------------------------------+
|              | EXTERNAL AUTHENTICATION                | EN 726-3        |                                                      |
|              +----------------------------------------+-----------------+------------------------------------------------------+
|              | ISSUER AUTHENTICATE                    | EMV-2           | Verify a signature of the card issuer.               |
|              +----------------------------------------+-----------------+------------------------------------------------------+
|              | MUTUAL AUTHENTICATE                    | ISO/IEC 7816-8  | Mutually authenticate the smart card and the         |
|              |                                        |                 | terminal.                                            |
|              +----------------------------------------+-----------------+------------------------------------------------------+
|              | UPDATE PSAM Parameter (online)         | EN 1546-3       | Modify the parameters in the PSAM (online).          |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0x84``   | ASK RANDOM                             | EN 726-3        | Request a random number from the smart card.         |
|              +----------------------------------------+-----------------+------------------------------------------------------+
|              | GET CHALLENGE                          | ISO/IEC 7816-4, | Request a random number from the smart card.         |
|              |                                        | OpenPGP         | (``P1P2=0000``)                                      |
|              +----------------------------------------+-----------------+------------------------------------------------------+
|              | UPDATE PSAM Parameter (offline)        | EN 1546-3       | Modify the parameters in the PSAM (offline).         |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0x86``   | GET PREVIOUS PSAM SIGNATURE            | EN 1546-3       | Repeat the computation and output of the last        |
|              |                                        |                 | signature received from the PSAM.                    |
|              +----------------------------------------+-----------------+------------------------------------------------------+
|              | GIVE RANDOM                            | EN 726-3        | Send a random number to the smart card.              |
|              +----------------------------------------+-----------------+------------------------------------------------------+
|              | GENERAL AUTHENTICATE                   | ISO/IEC 7816-4  |                                                      |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0x87``   | GENERAL AUTHENTICATE                   | ISO/IEC 7816-4, | ``P1``: algorithm (``06`` = RSA 1024, ``07`` =       |
|              |                                        | PIV             | RSA 2048)                                            |
|              |                                        |                 | ``P2``: key (``9A/9B/9E`` = authentication key 1/2/3,|
|              |                                        |                 | ``9C`` = signature key, ``9D`` = management key)     |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0x88``   | RUN GSM ALGORITHM                      | TS 51.011       | Execute a GSM-specific cryptographic algorithm.      |
|              +----------------------------------------+-----------------+------------------------------------------------------+
|              | INTERNAL AUTHENTICATION                | EN 726-3        |                                                      |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
| ``88 00 00`` | INTERNAL AUTHENTICATE                  | ISO/IEC 7816-4, | Authentication input related to algorithm            |
|              |                                        | OpenPGP         | (e.g. sign with a RSA private key some data)         |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|``0x90-0x9f`` | (invalid)                              | ISO/IEC 7816-4  | This allows the card to acknowledge with ``SW1=INS``.|
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0xA0``   | SEARCH BINARY                          | ISO/IEC 7816-9  | Search for a text string in a file with a            |
+--------------+                                        |                 | transparent structure.                               |
|   ``0xA1``   |                                        |                 |                                                      |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0xA2``   | SEARCH RECORD                          | ISO/IEC 7816-9  | Search for a text string in a file with a            |
|              +----------------------------------------+-----------------+ record-oriented structure.                           |
|              | SEEK                                   | TS 51.011,      |                                                      |
|              |                                        | EN 726-3        |                                                      |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0xA4``   | SELECT                                 | TS 51.011,      | Select a file.                                       |
|              |                                        | OpenPGP         | (``P1P2=0400``, command data partial AID).           |
|              +----------------------------------------+-----------------+------------------------------------------------------+
|              | SELECT (FILE)                          | ISO/IEC 7816-4  | Select a file.                                       |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0xA5``   | SELECT DATA                            | OpenPGP         | Select a DO (``P1`` = occurrence number,             |
|              |                                        |                 | ``P2`` = ``04``).                                    |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0xAC``   | CLOSE APPLICATION                      | EN 726-3        | Reset all attained access condition levels.          |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0xAE``   | EXECUTE                                | EN 726-3        | Execute a file.                                      |
|              +----------------------------------------+-----------------+------------------------------------------------------+
|              | GENERATE AUTHORISATION CRYPTOGRAM      | EMV             | Generate a signature for a payment transaction.      |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0xB0``   | READ BINARY                            | ISO/IEC 7816-4, | Read from a file with a transparent structure.       |
+--------------+                                        | TS 51.011       |                                                      |
|   ``0xB1``   |                                        |                 |                                                      |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0xB2``   | READ RECORD                            | TS 51.011       | Read data from a file with a record-oriented         |
|              +----------------------------------------+-----------------+ structure.                                           |
|              | READ RECORD(S)                         | ISO/IEC 7816-4  |                                                      |
+--------------+----------------------------------------+-----------------+                                                      |
|   ``0xB3``   | READ RECORD(S)                         | ISO/IEC 7816-4  |                                                      |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0xB4``   | READ BINARY STAMPED                    | ISO/IEC 7816-4  | Read data from a file with a transparent structure   |
|              |                                        |                 | that is secured with a cryptographic checksum.       |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0xB6``   | READ RECORD STAMPED                    | EN 726-3        | Read data from a file with a record-oriented         |
|              |                                        |                 | structure that is secured with a cryptographic       |
|              |                                        |                 | checksum.                                            |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0xC0``   | GET RESPONSE                           | TS 51.011,      | Request data from the smart card (``P1P2=0000``)     |
|              |                                        | OpenPGP         | (used with the T=0 transmission protocol).           |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0xC2``   | ENVELOPE PUT                           | EN 726-3        | Embed a command in a smart card command.             |
|              +----------------------------------------+-----------------+                                                      |
|              | ENVELOPE                               | ISO/IEC 7816-4  |                                                      |
+--------------+                                        |                 |                                                      |
|   ``0xC3``   |                                        |                 |                                                      |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0xCA``   | GET DATA                               | ISO/IEC 7816-4, | Read TLV-coded data objects (DO).                    |
+--------------+                                        | OpenPGP,        |                                                      |
|   ``0xCB``   |                                        | PIV: 0xCB       |                                                      |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0xCC``   | GET NEXT DATA                          | OpenPGP         | Read TLV-coded data objects (DO).                    |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0xD0``   | WRITE BINARY                           | ISO/IEC 7816-4  | Write to a file with a transparent structure using a |
+--------------+                                        |                 | logical AND/OR process.                              |
|   ``0xD1``   |                                        |                 |                                                      |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0xD2``   | WRITE RECORD                           | ISO/IEC 7816-4  | Write to a file with a record-oriented structure     |
|              |                                        |                 | using a logical AND/OR process.                      |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0xD4``   | EXTEND                                 | EN 726-3        | Extend a file.                                       |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0xD6``   | UPDATE BINARY                          | TS 51.011,      | Write to a file with a transparent structure.        |
+--------------+                                        | ISO/IEC7816-4   |                                                      |
|   ``0xD7``   |                                        |                 |                                                      |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0xD8``   | PUT KEY                                | OP              | Write one or more new keys or replace existing keys. |
|              +----------------------------------------+-----------------+------------------------------------------------------+
|              | LOAD KEY FILE                          | EN 726-3        | Load keys in files using cryptographic protection.   |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0xDA``   | PUT DATA                               | ISO/IEC 7816-4, | Write TLV-coded data objects (DO).                   |
+--------------+                                        | OpenPGP         |                                                      |
|   ``0xDB``   |                                        |                 |                                                      |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0xDC``   | UPDATE RECORD                          | TS 51.011,      | Write to a file with a linear fixed, linear variable |
+--------------+                                        | ISO/IEC 7816-4  | or cyclic structure.                                 |
|   ``0xDD``   |                                        |                 |                                                      |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0xE0``   | CREATE FILE                            | ISO/IEC 7816-9  | Create a new file.                                   |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0xE2``   | APPEND RECORD                          | ISO/IEC 7816-4  | Insert a new record in a file with a linear fixed    |
|              |                                        |                 | structure.                                           |
|              +----------------------------------------+-----------------+------------------------------------------------------+
|              | CREATE RECORD                          | EN 726-3        | Create a new record in a record-oriented file.       |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0xE4``   | DELETE                                 | OP              | Delete a uniquely identifiable object                |
|              |                                        |                 | (such as a load file, application or key).           |
|              +----------------------------------------+-----------------+------------------------------------------------------+
|              | DELETE FILE                            | ISO/IEC 7816-9  | Delete a file.                                       |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0xE6``   | TERMINATE DF                           | ISO/IEC 7816-9, | Irreversibly block a DF.                             |
|              |                                        | OpenPGP         | (``P1P2=0000``)                                      |
|              +----------------------------------------+-----------------+------------------------------------------------------+
|              | INSTALL                                | OP              | Install an application by invoking various oncard    |
|              |                                        |                 | functions of the card manager and/or security domain.|
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0xE8``   | LOAD                                   | OP              | Load an application by transferring the load file.   |
|              +----------------------------------------+-----------------+------------------------------------------------------+
|              | TERMINATE EF                           | ISO/IEC 7816-9  | Irreversibly block an EF.                            |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0xF0``   | SET STATUS                             | OP              | Write life-cycle state data for the card manager,    |
|              |                                        |                 | application and load file.                           |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0xF1``   | GET VERSION                            | OpenPGP         | Get OpenPGP specification version                    |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0xF2``   | GET STATUS                             | ISO/IEC 7816-4, | Read the life-cycle state information of the card    |
|              |                                        | OP              | manager, application and load file.                  |
|              +----------------------------------------+-----------------+------------------------------------------------------+
|              | STATUS                                 | TS 51.011       | Read various data from the currently selected file.  |
|              +----------------------------------------+-----------------+------------------------------------------------------+
|              | SET PIN RETRIES                        | OpenPGP Yubikey | Set PIN retries counters                             |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0xFA``   | SLEEP                                  | TS 51.011       | Obsolete command for setting the smart card in a     |
|              |                                        |                 | power-saving state.                                  |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+
|   ``0xFE``   | TERMINATE CARD USAGE                   | ISO/IEC 7816-9  | Irreversibly block a smart card.                     |
+--------------+----------------------------------------+-----------------+------------------------------------------------------+

Status word
-----------

The status word consist in two bytes, ``SW1`` and ``SW2``. ``SW1`` can only be equals to ``6x`` or ``9x``, but not ``60`` (this value encodes a NULL byte in the transmission protocol).

+-------------+--------------------------------------------------------------------------------------------------------------+
| ``SW1-SW2`` | Message                                                                                                      |
+=============+==============================================================================================================+
|  ``6x xx``  | Transmission protocol related codes                                                                          |
+-+-----------+--------------------------------------------------------------------------------------------------------------+
| |  ``60 xx``| (invalid value in ISO/IEC 7816-4)                                                                            |
+-+-----------+--------------------------------------------------------------------------------------------------------------+
| |  ``61 xx``| Process completed normally, SW2 indicates the number of response bytes still available (use "GET RESPONSE"). |
+-+-----------+--------------------------------------------------------------------------------------------------------------+
| |  ``62 xx``| Process completed with warning (State of non-volatile memory is unchanged).                                  |
+-+-+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6200`` | No information given                                                                                         |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6281`` | Returned data may be corrupted                                                                               |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6282`` | The end of the file has been reached before the end of reading (Le bytes)                                    |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6283`` | Invalid DF ; Selected file invalidated.                                                                      |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6284`` | Selected file is not valid. File descriptor error. FCI not formatted according to ISO.                       |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6285`` | Selected file in termination state.                                                                          |
|   |         | EMV: No input data available from a sensor on the card. No Purse Engine enslaved for R3bc.                   |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6286`` | No input data available from a sensor on the card                                                            |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``62A2`` | EMV: Wrong R-MAC.                                                                                            |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``62A4`` | EMV: Card locked (during reset).                                                                             |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``62Cx`` | EMV: Counter with value x (command dependent).                                                               |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``62F1`` | EMV: Wrong C-MAC.                                                                                            |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``62F3`` | EMV: Internal reset.                                                                                         |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``62F5`` | EMV: Default agent locked.                                                                                   |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``62F7`` | EMV: Cardholder locked.                                                                                      |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``62F8`` | EMV: Basement is current agent.                                                                              |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``62F9`` | EMV: CALC Key Set not unblocked.                                                                             |
+-+-+---------+--------------------------------------------------------------------------------------------------------------+
| |  ``63 xx``| Process completed with warning (State of non-volatile memory has changed).                                   |
+-+-+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6300`` | Authentication failed. Invalid secret code or forbidden value.                                               |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6381`` | File filled up by the last write. Loading/updating is not allowed.                                           |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6383`` | EMV: Reader key not supported.                                                                               |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6384`` | EMV: Plaintext transmission not supported.                                                                   |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6385`` | EMV: Secured transmission not supported.                                                                     |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6386`` | EMV: Volatile memory is not available.                                                                       |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6387`` | EMV: Non-volatile memory is not available.                                                                   |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6388`` | EMV: Key number not valid.                                                                                   |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6389`` | EMV: Key length is not correct.                                                                              |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``63Cx`` | Counter provided by 'x' (valued from 0 to 15) (exact meaning depending on the command).                      |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``63F1`` | More data expected.                                                                                          |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``63F2`` | More data expected and proactive command pending.                                                            |
+---+---------+--------------------------------------------------------------------------------------------------------------+

+-------------+--------------------------------------------------------------------------------------------------------------+
| ``SW1-SW2`` | Error message (``SW1=64..6F``)                                                                               |
+=+===========+==============================================================================================================+
|``64-6F xx`` | En error occurred and no data shall be in the response                                                       |
+-+-----------+--------------------------------------------------------------------------------------------------------------+
| |  ``64 xx``| Execution error (State of non-volatile memory is unchanged).                                                 |
+-+-+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6400`` | Execution error.                                                                                             |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6401`` | Command timeout. Immediate response required by the card ; Interface error.                                  |
+-+-+---------+--------------------------------------------------------------------------------------------------------------+
| |  ``65 xx``| Execution error (State of non-volatile memory has changed).                                                  |
+-+-+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6501`` | Memory failure. There have been problems in writing or reading the EEPROM.                                   |
|   |         | Other hardware problems may also bring this error.                                                           |
|   |         | NFCLib: Create key failed.                                                                                   |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6502`` | NFCLib: SAM key reference invalid.                                                                           |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6503`` | NFCLib: SAM key usage counter number.                                                                        |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6581`` | Write problem ; Memory failure ; Unknown mode                                                                |
+-+-+---------+--------------------------------------------------------------------------------------------------------------+
| |  ``66 xx``| Execution error (Security-related issues).                                                                   |
+-+-+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6600`` | OpenPGP: Security-related issues (reserved for UIF in this application).                                     |
|   |         | EMV: Error while receiving (timeout).                                                                        |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6601`` | EMV: Error while receiving (character parity error).                                                         |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6602`` | EMV: Wrong checksum.                                                                                         |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6603`` | EMV: The current DF file without FCI.                                                                        |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6604`` | EMV: No SF or KF under the current DF.                                                                       |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6669`` | EMV: Incorrect Encryption/Decryption Padding.                                                                |
+-+-+---------+--------------------------------------------------------------------------------------------------------------+
| |  ``67 xx``| (proprietary except ``6700``)                                                                                |
+-+-+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6700`` | Incorrect length or address range error, incorrect parameter P3 (ISO code, CLA INS P1 P2 supported).         |
+-+-+---------+--------------------------------------------------------------------------------------------------------------+
| |  ``68 xx``| Checking error. Functions in CLA not supported.                                                              |
+-+-+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6800`` | The requested function is not supported by the card.                                                         |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6881`` | Logical channel not supported                                                                                |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6882`` | Secure messaging not supported                                                                               |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6883`` | Final chained command expected                                                                               |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6884`` | Command chaining is not supported                                                                            |
+-+-+---------+--------------------------------------------------------------------------------------------------------------+
| |  ``69 xx``| Checking error. Command not allowed.                                                                         |
+-+-+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6900`` | No successful transaction executed during session.                                                           |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6901`` | Command not accepted (inactive state).                                                                       |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6981`` | Cannot select indicated file, command not compatible with file organization/structure.                       |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6982`` | Access conditions not fulfilled, security status not satisfied, SM incorrect.                                |
|   |         | EMV: Security condition not satisfied.                                                                       |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6983`` | Secret code locked, authentication method blocked.                                                           |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6984`` | Referenced data invalidated (reversibly blocked). Reference data invalid.                                    |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6985`` | No currently selected EF, no command to monitor, no Transaction Manager File, conditions of use not satisfied|
|   |         | NFCLib: Access conditions not satisfied / Host authentication KUC required.                                  |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6986`` | Command not allowed (no current EF).                                                                         |
|   |         | NFCLib: Command not allowed (part1 of authentication procedure has to be executed first).                    |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6987`` | Expected SM data objects missing.                                                                            |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6988`` | Incorrect SM data objects.                                                                                   |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6996`` | EMV: Data must be updated again.                                                                             |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``69E1`` | EMV: POL1 of the currently Enabled Profile prevents this action.                                             |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``69F0`` | EMV: Permission Denied.                                                                                      |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``69F1`` | EMV: Permission Denied - Missing Privilege.                                                                  |
+-+-+---------+--------------------------------------------------------------------------------------------------------------+
| |  ``6A xx``| Checking error. Wrong parameters P1-P2.                                                                      |
+-+-+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6A00`` | Bytes P1 and/or P2 are incorrect.                                                                            |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6A80`` | Incorrect data field in the command data field.                                                              |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6A81`` | Card is blocked or command not supported.                                                                    |
|   |         | EMV: Function not supported.                                                                                 |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6A82`` | File or application not found.                                                                               |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6A83`` | Record not found.                                                                                            |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6A84`` | Not enough memory space in the file.                                                                         |
|   |         | NFCLib: SAM Host protection error, only valid in AV2 mode.                                                   |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6A85`` | Lc inconsistent with TLV structure.                                                                          |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6A86`` | Incorrect P1 or P2 parameter.                                                                                |
|   |         | NFCLib: File not found.                                                                                      |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6A87`` | The P3 (or Nc) value is not consistent with the P1 and P2 values.                                            |
|   |         | EMV: Lc inconsistent with P1-P2.                                                                             |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6A88`` | Referenced data not found.                                                                                   |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6A89`` | File already exists.                                                                                         |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6A8A`` | DF name already exists.                                                                                      |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6AF0`` | EMV: Wrong parameter value.                                                                                  |
+-+-+---------+--------------------------------------------------------------------------------------------------------------+
| |  ``6B xx``| (proprietary except ``6B00``)                                                                                |
+-+-+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6B00`` | Incorrect reference; illegal address; Invalid P1 or P2 parameter (but CLA INS supported).                    |
+-+-+---------+--------------------------------------------------------------------------------------------------------------+
| |  ``6C xx``| Incorrect P3 length (SW2 encodes the number of available data bytes).                                        |
| |           | NFCLib: File not found / Wrong Le field.                                                                     |
+-+-+---------+--------------------------------------------------------------------------------------------------------------+
| |  ``6D xx``| (proprietary except ``6D00``)                                                                                |
+-+-+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6D00`` | CLA supported, but INS not programmed or invalid or not allowed.                                             |
+-+-+---------+--------------------------------------------------------------------------------------------------------------+
| |  ``6E xx``| (proprietary except ``6E00``)                                                                                |
+-+-+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6E00`` | CLA not supported.                                                                                           |
+-+-+---------+--------------------------------------------------------------------------------------------------------------+
| |  ``6F xx``| (proprietary except ``6F00``)                                                                                |
+-+-+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6F00`` | No precise diagnostics (command not supported and no precise diagnosis given).                               |
|   |         | EMV: Command aborted - more exact diagnosis not possible (e.g., operating system error).                     |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``6FFF`` | EMV: Card dead (overuse, ...).                                                                               |
+---+---------+--------------------------------------------------------------------------------------------------------------+

+-------------+--------------------------------------------------------------------------------------------------------------+
| ``SW1-SW2`` | Message                                                                                                      |
+=============+==============================================================================================================+
|  ``9x xx``  | (proprietary except ``9000``)                                                                                |
+-+-----------+--------------------------------------------------------------------------------------------------------------+
| |  ``90 xx``| Correct execution.                                                                                           |
+-+-+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9000`` | Command executed without error (success).                                                                    |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9004`` | EMV: PIN not successfully verified, 3 or more PIN tries left.                                                |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9008`` | EMV: Key/file not found.                                                                                     |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``901E`` | NFCLib: Correct execution,Authentication failed.                                                             |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9080`` | EMV: Unblock Try Counter has reached zero.                                                                   |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``90BE`` | NFCLib: Mifare PICC sent incorrect amount of data,wrong length of CMAC.                                      |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``90BF`` | NFCLib: Mifare PICC returned error.                                                                          |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``90E0`` | NFCLib: No response from card.                                                                               |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``90E1`` | NFCLib: ISO 14443 protocol error.                                                                            |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``90E2`` | NFCLib: Parity error.                                                                                        |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``90E3`` | NFCLib: Buffer overflow.                                                                                     |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``90E4`` | NFCLib: ACK expected, CRC mismatch.                                                                          |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``90E5`` | NFCLib: RF field inactive.                                                                                   |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``90E6`` | NFCLib: Temperature error.                                                                                   |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``90E7`` | NFCLib: FIFO write error.                                                                                    |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``90E8`` | NFCLib: Collision error.                                                                                     |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``90E9`` | NFCLib: transaction error.                                                                                   |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``90EA`` | NFCLib: Correct execution, Authentication failed.                                                            |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``90EB`` | NFCLib: Correct execution, Authentication failed.                                                            |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``90EC`` | NFCLib: Correct execution, Authentication failed.                                                            |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``90ED`` | NFCLib: Correct execution, Authentication failed.                                                            |
+-+-+---------+--------------------------------------------------------------------------------------------------------------+
| |  ``91 xx``|                                                                                                              |
+-+-+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9100`` | Purse Balance error cannot perform transaction.                                                              |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9101`` | EMV: States.activity, States.lock Status or States.lockable has wrong value.                                 |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9102`` | Purse Balance error.                                                                                         |
|   |         | EMV: Transaction number reached its limit.                                                                   |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``910C`` | EMV: No changes.                                                                                             |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``910E`` | EMV: Insufficient NV-Memory to complete command.                                                             |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``911C`` | EMV: Command code not supported.                                                                             |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``911E`` | EMV: CRC or MAC does not match data.                                                                         |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9140`` | EMV: Invalid key number specified.                                                                           |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``917E`` | EMV: Length of command string invalid.                                                                       |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``919D`` | EMV: Not allow the requested command.                                                                        |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``919E`` | EMV: Value of the parameter invalid.                                                                         |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``91A0`` | EMV: Requested AID not present on PICC.                                                                      |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``91A1`` | EMV: Unrecoverable error within application.                                                                 |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``91AE`` | EMV: Authentication status does not allow the requested command.                                             |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``91AF`` | EMV: Additional data frame is expected to be sent.                                                           |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``91BE`` | EMV: Out of boundary.                                                                                        |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``91C1`` | EMV: Unrecoverable error within PICC.                                                                        |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``91CA`` | EMV: Previous Command was not fully completed.                                                               |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``91CD`` | EMV: PICC was disabled by an unrecoverable error.                                                            |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``91CE`` | EMV: Number of Applications limited to 28.                                                                   |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``91DE`` | EMV: File or application already exists.                                                                     |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``91EE`` | EMV: Could not complete NV-write operation due to loss of power.                                             |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``91F0`` | EMV: Specified file number does not exist.                                                                   |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``91F1`` | EMV: Unrecoverable error within file.                                                                        |
+-+-+---------+--------------------------------------------------------------------------------------------------------------+
| |  ``92 xx``| Memory error.                                                                                                |
+-+-+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9202`` | Write problem / Memory failure.                                                                              |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9210`` | EMV: Insufficient memory. No more storage available.                                                         |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9240`` | Error, memory problem.                                                                                       |
|   |         | EMV: Writing to EEPROM not successful.                                                                       |
+-+-+---------+--------------------------------------------------------------------------------------------------------------+
| |  ``93 xx``|                                                                                                              |
+-+-+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9301`` | EMV: Integrity error.                                                                                        |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9302`` | EMV: Candidate S2 invalid.                                                                                   |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9303`` | EMV: Application is permanently locked.                                                                      |
+-+-+---------+--------------------------------------------------------------------------------------------------------------+
| |  ``94 xx``| File error.                                                                                                  |
+-+-+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9401`` | EMV: Candidate currency code does not match purse currency.                                                  |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9402`` | EMV: Candidate amount too high.                                                                              |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9402`` | EMV: Address range exceeded.                                                                                 |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9403`` | EMV: Candidate amount too low.                                                                               |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9404`` | Purse selection error or invalid purse.                                                                      |
|   |         | EMV: Candidate amount too low.                                                                               |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9405`` | EMV: Problems in the data field.                                                                             |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9406`` | Invalid purse detected during the replacement debit step.                                                    |
|   |         | EMV: Required MAC unavailable.                                                                               |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9407`` | EMV: Bad currency : purse engine has no slot with R3bc currency.                                             |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9408`` | Key file selection error.                                                                                    |
|   |         | EMV: R3bc currency not supported in purse engine.                                                            |
|   |         | EMV: Selected file type does not match command.                                                              |
+-+-+---------+--------------------------------------------------------------------------------------------------------------+
| |  ``95 xx``|                                                                                                              |
+-+-+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9580`` | EMV: Bad sequence.                                                                                           |
+-+-+---------+--------------------------------------------------------------------------------------------------------------+
| |  ``96 xx``|                                                                                                              |
+-+-+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9681`` | EMV: Slave not found.                                                                                        |
+-+-+---------+--------------------------------------------------------------------------------------------------------------+
| |  ``97 xx``|                                                                                                              |
+-+-+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9700`` | EMV: PIN blocked and Unblock Try Counter is 1 or 2.                                                          |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9702`` | EMV: Main keys are blocked.                                                                                  |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9704`` | EMV: PIN not successfully verified, 3 or more PIN tries left.                                                |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9784`` | EMV: Base key.                                                                                               |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9785`` | EMV: Limit exceeded - C-MAC key.                                                                             |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9786`` | EMV: SM error - Limit exceeded - R-MAC key.                                                                  |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9787`` | EMV: Limit exceeded - sequence counter.                                                                      |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9788`` | EMV: Limit exceeded - R-MAC length.                                                                          |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9789`` | EMV: Service not available.                                                                                  |
+-+-+---------+--------------------------------------------------------------------------------------------------------------+
| |  ``98 xx``| Security error.                                                                                              |
+-+-+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9800`` | Warning.                                                                                                     |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9802`` | EMV: No PIN defined.                                                                                         |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9804`` | Access authorization not fulfilled.                                                                          |
|   |         | EMV: Access conditions not satisfied, authentication failed.                                                 |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9806`` | Access authorization in Debit not fulfilled for the replacement debit step  .                                |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9820`` | No temporary transaction key established.                                                                    |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9834`` | Error, Update SSD order sequence not respected                                                               |
|   |         | (should be used if SSD Update commands are received out of sequence).                                        |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9835`` | EMV: ASK RANDOM or GIVE RANDOM not executed.                                                                 |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9840`` | EMV: PIN verification not successful.                                                                        |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9850`` | EMV: INCREASE or DECREASE could not be executed because a limit has been reached.                            |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9862`` | EMV: Authentication Error, application specific (incorrect MAC).                                             |
+-+-+---------+--------------------------------------------------------------------------------------------------------------+
| |  ``99 xx``|                                                                                                              |
+-+-+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9900`` | EMV: 1 PIN try left.                                                                                         |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9904`` | EMV: PIN not successfully verified, 1 PIN try left.                                                          |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9985`` | EMV: Wrong status - Cardholder lock.                                                                         |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9986`` | EMV: Missing privilege.                                                                                      |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9987`` | EMV: PIN is not installed.                                                                                   |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9988`` | EMV: Wrong status - R-MAC state.                                                                             |
+-+-+---------+--------------------------------------------------------------------------------------------------------------+
| |  ``9A xx``|                                                                                                              |
+-+-+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9A00`` | EMV: 2 PIN try left.                                                                                         |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9A04`` | EMV: PIN not successfully verified, 2 PIN try left.                                                          |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9A71`` | EMV: Wrong parameter value - Double agent AID.                                                               |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9A72`` | EMV: Wrong parameter value - Double agent Type.                                                              |
+-+-+---------+--------------------------------------------------------------------------------------------------------------+
| |  ``9D xx``|                                                                                                              |
+-+-+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9D05`` | EMV: Incorrect certificate type.                                                                             |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9D07`` | EMV: Incorrect session data size.                                                                            |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9D08`` | EMV: Incorrect DIR file record size.                                                                         |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9D09`` | EMV: Incorrect FCI record size.                                                                              |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9D0A`` | EMV: Incorrect code size.                                                                                    |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9D10`` | EMV: Insufficient memory to load application.                                                                |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9D11`` | EMV: Invalid AID.                                                                                            |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9D12`` | EMV: Duplicate AID.                                                                                          |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9D13`` | EMV: Application previously loaded.                                                                          |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9D14`` | EMV: Application history list full.                                                                          |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9D15`` | EMV: Application not open.                                                                                   |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9D17`` | EMV: Invalid offset.                                                                                         |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9D18`` | EMV: Application already loaded.                                                                             |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9D19`` | EMV: Invalid certificate.                                                                                    |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9D1A`` | EMV: Invalid signature.                                                                                      |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9D1B`` | EMV: Invalid KTU.                                                                                            |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9D1D`` | EMV: MSM controls not set.                                                                                   |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9D1E`` | EMV: Application signature does not exist.                                                                   |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9D1F`` | EMV: KTU does not exist.                                                                                     |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9D20`` | EMV: Application not loaded.                                                                                 |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9D21`` | EMV: Invalid Open command data length.                                                                       |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9D30`` | EMV: Check data parameter is incorrect (invalid start address).                                              |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9D31`` | EMV: Check data parameter is incorrect (invalid length).                                                     |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9D32`` | EMV: Check data parameter is incorrect (illegal memory check area).                                          |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9D40`` | EMV: Invalid MSM Controls ciphertext.                                                                        |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9D41`` | EMV: MSM controls already set.                                                                               |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9D42`` | EMV: Set MSM Controls data length less than 2 bytes.                                                         |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9D43`` | EMV: Invalid MSM Controls data length.                                                                       |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9D44`` | EMV: Excess MSM Controls ciphertext.                                                                         |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9D45`` | EMV: Verification of MSM Controls data failed.                                                               |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9D50`` | EMV: Invalid MCD Issuer production ID.                                                                       |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9D51`` | EMV: Invalid MCD Issuer ID.                                                                                  |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9D52`` | EMV: Invalid set MSM controls data date.                                                                     |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9D53`` | EMV: Invalid MCD number.                                                                                     |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9D54`` | EMV: Reserved field error.                                                                                   |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9D55`` | EMV: Reserved field error.                                                                                   |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9D56`` | EMV: Reserved field error.                                                                                   |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9D57`` | EMV: Reserved field error.                                                                                   |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9D60`` | EMV: MAC verification failed.                                                                                |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9D61`` | EMV: Maximum number of unblocks reached.                                                                     |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9D62`` | EMV: Card was not blocked.                                                                                   |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9D63`` | EMV: Crypto functions not available.                                                                         |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9D64`` | EMV: No application loaded.                                                                                  |
+-+-+---------+--------------------------------------------------------------------------------------------------------------+
| |  ``9E xx``|                                                                                                              |
+-+-+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9E00`` | EMV: PIN not installed.                                                                                      |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9E04`` | EMV: PIN not successfully verified, PIN not installed.                                                       |
+-+-+---------+--------------------------------------------------------------------------------------------------------------+
| |  ``9F xx``| Success, XX bytes of data available to be read using ``GET RESPONSE``.                                       |
+-+-+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9F00`` | EMV: PIN blocked and Unblock Try Counter is 3.                                                               |
+---+---------+--------------------------------------------------------------------------------------------------------------+
|   |``9F04`` | EMV: PIN not successfully verified, PIN blocked and Unblock Try Counter is 3.                                |
+---+---------+--------------------------------------------------------------------------------------------------------------+
