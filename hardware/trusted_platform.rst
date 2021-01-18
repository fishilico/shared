Trusted Platform Module and Trusted Boot
========================================

Definitions and history
-----------------------

*Trusted Platform Module* (TPM) is a secure cryptoprocessor, ie. a dedicated microcontroller designed to secure hardware through integrated cryptographic keys.
TPM was conceived by a computer industry consortium called *Trusted Computing Group* (TCG) and was standardised in 2009 as ISO/IEC 11889.

Nowadays, there are two main versions of TPM:

* TPM 1.2 (from TPM Main Specification Version 1.2) was published in 2011
* TPM 2.0 (from TPM Library Specification 2.0) was published in 2016 (after some revisions in 2013-2014)

This specifications include the *TPM Software Stack* specification (TSS).

A TPM can be used to hold keys and to attest the integrity of the boot components.
This last part is called *Trusted Boot*, which is different from *Secure Boot* (the use of firmware/software that is signed by trusted Certificate Authorities, implemented by root certificated in the BIOS).

Sources:

* https://en.wikipedia.org/wiki/Trusted_Platform_Module
* https://www.trustedcomputinggroup.org/resource/tpm-library-specification/
* https://www.trustedcomputinggroup.org/tcg-efi-protocol-specification


Trusted Boot and PCRs
---------------------

The TPM contains several *Platform Configuration Registers* (PCRs) that measure the content of several components during the boot process.
Each measure is computed by extending a cryptographic hash in a piece of memory (called register).
The extension of hashes into a PCR is described in *Trusted Platform Module Library Part 3: Commands, family 2.0, level 00, revision 01.16 (Section 22.2.1)* as::

    PCR <- SHA-1(PCR | SHA-1(data))

There are at least 16 PCR registers.
With TPM 1.2, each PCR is 160-bit long (ie. 20 bytes) and stores a SHA-1 digest.

For example on a system with a TPM 1.2 chipset:

.. code-block:: text

    $ realpath /sys/class/tpm/tpm0/device
    /sys/devices/pnp0/00:06

    $ cat /sys/class/tpm/tpm0/device/pcrs
    PCR-00: 2F F0 8D 91 4E BC 59 64 44 29 6C C9 72 D6 BF 9A 2A B4 42 F8
    PCR-01: 3A 3F 78 0F 11 A4 B4 99 69 FC AA 80 CD 6E 39 57 C3 3B 22 75
    PCR-02: 0F C6 7E FF FE 91 C0 55 29 31 C4 BA A8 A3 10 17 38 6D B3 B3
    PCR-03: 3A 3F 78 0F 11 A4 B4 99 69 FC AA 80 CD 6E 39 57 C3 3B 22 75
    PCR-04: AC 47 EA 97 E5 79 A0 98 AE 6A B7 5E 8B A3 2D 21 B1 5C 6E B3
    PCR-05: 4E 5B 17 56 1D 1C 28 9D 65 7F 50 21 14 09 B7 10 09 5D F4 49
    PCR-06: 3A 3F 78 0F 11 A4 B4 99 69 FC AA 80 CD 6E 39 57 C3 3B 22 75
    PCR-07: C0 20 0E CC C0 82 11 5C 31 24 34 FD 09 86 14 F0 40 D6 87 35
    PCR-08: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    PCR-09: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    PCR-10: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    PCR-11: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    PCR-12: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    PCR-13: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    PCR-14: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    PCR-15: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    PCR-16: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    PCR-17: FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
    PCR-18: FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
    PCR-19: FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
    PCR-20: FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
    PCR-21: FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
    PCR-22: FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
    PCR-23: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

On another system with a TPM 2.0 chipset and ``tpm2-tools`` installed:

.. code-block:: text

    $ tpm2_pcrlist
    sha1 :
      0  : be0c07a17884a641fb032c58e1b29b5e55b592ca
      1  : b8ae5dbf4bc4b0e83d6ab03de7f28f552025a19f
      2  : 2fb13496781b67badc57a2f17bb90a48229fa99c
      3  : b2a83b0ebf2f8374299a5b2bdfc31ea955ad7236
      4  : c9455a8380b5e6930a17328884758522b181a829
      5  : ecb79fc7330e9bfea366550e44a4e6515e48759a
      6  : b2a83b0ebf2f8374299a5b2bdfc31ea955ad7236
      7  : 6d7206871c9c6f38ad3997baceebee95dadec04d
      8  : 9226d39fca0eb214e219c18f925d5a7b8ebb66ee
      9  : 0000000000000000000000000000000000000000
      10 : 0000000000000000000000000000000000000000
      11 : 0000000000000000000000000000000000000000
      12 : 0000000000000000000000000000000000000000
      13 : 0000000000000000000000000000000000000000
      14 : 0000000000000000000000000000000000000000
      15 : 0000000000000000000000000000000000000000
      16 : 0000000000000000000000000000000000000000
      17 : ffffffffffffffffffffffffffffffffffffffff
      18 : ffffffffffffffffffffffffffffffffffffffff
      19 : ffffffffffffffffffffffffffffffffffffffff
      20 : ffffffffffffffffffffffffffffffffffffffff
      21 : ffffffffffffffffffffffffffffffffffffffff
      22 : ffffffffffffffffffffffffffffffffffffffff
      23 : 0000000000000000000000000000000000000000
    sha256 :
      0  : 9467b382b250c73c3c666a3f0487700bd90bd34fdea8ae22ab178ea0dd954db2
      1  : 593d8d5f77280ad66bcefbd5ed7cc73068e6bf623b02c3d1e87f448dd264634d
      2  : d3b8a3834bf00d10efe28562a8030f0d0980006a9940e43aeaa400ede926fc7f
      3  : 3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969
      4  : 8e094f5c060fe9e67a723741feeaf4f038842e7d6594ae4c7b01f20084d54906
      5  : a032e5e7444c4f10b08165f12dfdc9fef07c6c43933a96f14a53197df6b10d1d
      6  : 3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969
      7  : 730777cfa2b4c2cf67a54ce7c80d7d15cebd0a443d1bc320e43fe338812ea67b
      8  : 4a7bbed9c2cc36af0d60403c99dc7478b35c8f746f4324324e0e85a409c27786
      9  : 0000000000000000000000000000000000000000000000000000000000000000
      10 : 0000000000000000000000000000000000000000000000000000000000000000
      11 : 0000000000000000000000000000000000000000000000000000000000000000
      12 : 0000000000000000000000000000000000000000000000000000000000000000
      13 : 0000000000000000000000000000000000000000000000000000000000000000
      14 : 0000000000000000000000000000000000000000000000000000000000000000
      15 : 0000000000000000000000000000000000000000000000000000000000000000
      16 : 0000000000000000000000000000000000000000000000000000000000000000
      17 : ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
      18 : ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
      19 : ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
      20 : ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
      21 : ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
      22 : ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
      23 : 0000000000000000000000000000000000000000000000000000000000000000


The component which is measured by each PCR depends on the BIOS and Operating System which is used.
Several sources of information document what is used for each PCR:

* TCG norm
* trousers (https://sourceforge.net/p/trousers/tpm-luks/ci/master/tree/tpm-luks/tpm-luks-gen-tgrub-pcr-values)
* Windows Insight (https://github.com/ernw/Windows-Insight/tree/master/articles/TPM)
* Windows BitLocker, which seals data using PCRs 0, 2, 4, 5, 8, 9, 10, 11 by default

+-----------+-----------------+-----------------------------------------------------------------------------+
| PCR Index | Measured by     | Description                                                                 |
+===========+=================+=============================================================================+
| ``0``     | CRTM and BIOS   | CRTM (Core Root of Trust of Measurement), BIOS and Host Platform Extensions |
+-----------+-----------------+-----------------------------------------------------------------------------+
| ``1``     | BIOS            | Host Platform Configuration (including BIOS configuration)                  |
+-----------+-----------------+-----------------------------------------------------------------------------+
| ``2``     | BIOS            | Option ROM Code                                                             |
+-----------+-----------------+-----------------------------------------------------------------------------+
| ``3``     | BIOS            | Option ROM Configuration and Data                                           |
+-----------+-----------------+-----------------------------------------------------------------------------+
| ``4``     | BIOS            | IPL Code (Initial Program Load, usually the 0x1b8 first bytes of a MBR)     |
+-----------+-----------------+-----------------------------------------------------------------------------+
| ``5``     | BIOS            | IPL Configuration and Data (eg. the partition table on a MBR disk)          |
+-----------+-----------------+-----------------------------------------------------------------------------+
| ``6``     | BIOS            | State Transition and Wake Events                                            |
+-----------+-----------------+-----------------------------------------------------------------------------+
| ``7``     | BIOS            | Host Platform Manufacturer Control                                          |
+-----------+-----------------+-----------------------------------------------------------------------------+
| ``8-15``  |                 | Used by the OS                                                              |
+-----------+-----------------+-----------------------------------------------------------------------------+
| ``8``     | Windows MBR     | VBR (first stage) = NTFS Boot Sector                                        |
+-----------+-----------------+-----------------------------------------------------------------------------+
| ``9``     | Windows VBR-1   | VBR (1st and 2nd stages) = NTFS Boot Sector and Boot Block                  |
+-----------+-----------------+-----------------------------------------------------------------------------+
| ``10``    | Windows VBR-2   | ``SHA-1(bootmgr)``                                                          |
+-----------+-----------------+-----------------------------------------------------------------------------+
| ``11``    | Windows bootmgr | TPM Lock (zero when the PCR is used to unseal keys,                         |
|           |                 | non-zero to lock later accesses)                                            |
+-----------+-----------------+-----------------------------------------------------------------------------+

On x86-based systems, the Master Boot Record (MBR) may access TPM functions using interrupt ``INT 1Ah`` with ``AH=BBh`` in real mode.
For example triggering this interrupt with ``AX=BB00h`` calls ``TCG_StatusCheck`` and with ``AX=BB07h`` calls ``TCG_CompactHashLogExtendEvent``.

In order to configure Trusted Boot, there are several possibilities:

* Configure Intel Trusted Execution Technology (Intel TXT)
* Follow instructions for Qubes OS's Anti Evil Maid (AEM) module: https://github.com/QubesOS/qubes-antievilmaid

On Linux, there are also special files, ``/sys/kernel/security/tpm0/ascii_bios_measurements`` and ``/sys/kernel/security/tpm0/binary_bios_measurements``.
These files display the *event log* of the TPM, which is all the data that the BIOS hashes into the PCRs.
The kernel module which creates these files is written in https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/char/tpm/eventlog?h=v5.1

Asymmetric-Key Cryptography on TPM 1.2
--------------------------------------

A TPM 1.2 contains a RSA key called the *Endorsement Key* (EK). Its public portion is the PUBEK and its private one is the PRIVEK.
This key is used to encrypt the shared secret which is used in order to establish the *TPM Owner*, as well as to encrypt *Attestation Identity Key* (AIK) values and credentials.

Taking ownership of a TPM is the act of:

* clearing a previous owner by calling ``TPM_ForceClear`` with established physical presence, for example from a menu in the BIOS ;
* defining a new shared secret by calling ``TPM_TakeOwnership``.

In order to authenticate to a TPM, the TPM Owner AuthData has to be transmitted. Several protocols can be used to do this:

* *Object-Independent Authorization Protocol* (OIAP)
* *Object-Specific Authorization Protocol* (OSAP)
* *Delegate-Specific Authorization Protocol* (DSAP).

In order to manage AuthData, several protocols exist too:

* *AuthData Insertion Protocol* (ADIP), for entity creation
* *AuthData Change Protocol* (ADCP)
* *Asymmetric Authorization Change Protocol* (AACP)

``TPM_TakeOwnership`` creates a new *Storage Root Key* (SRK) and a new ``tpmProof`` value.
This is tied to the concept of *Root of Trust for Storage* (RTS), which consists in protecting (encrypting) data held in storage devices that are external to the TPM.

The *Endorsement Key* (EK) is the *Root Trust for Reporting* (RTR), a cryptographic identity used to distinguish and authenticate an individual TPM.

An *Attestation Identity Key* (AIK) is an alias for the *Endorsement Key* (EK) that can be generated after establishing the TPM Owner and only used to sign information generated internally by the TPM.
It can be an RSA keypair, encrypted using the EK.
An AIK keypair is generated using ``TPM_MakeIdentity`` and is unwrapped using ``TPM_ActivateIdentity`` with AIK credentials.
An encrypted AIK keypair can be exported and stored on some general-purpose storage device.

In summary, there are 5 kinds of keys in a TPM 1.2:

* *Endorsement Key* (EK), created by the manufacturer and used to distinguish a TPM
* *Storage Root Key* (SRK), created when configuring the ownership of the TPM
* *Storage Key* (SK), used to encrypt other elements such as the *Binding Key*
* *Binding Key* (BK), used to encrypt little data blocks used by the TPM
* *Attestation Identity Key* (AIK), used to sign data generated by the TPM (in order for example to allow applications to authenticate the TPM)

TPM 2.0 changes
---------------

TPM 2.0 adds the support of Elliptic-Curve Cryptography (ECC) and the concept of Primary Seeds in order to derive objects using a Key Derivation Function (KDF) and parameters provided by a caller.
This allows using EKs for many different Elliptic-Curve parameters (also named *templates*) without requiring a huge amount of Non-Volatile memory.

* The seed used to generate EKs is called the *Endorsement Primary Seed* (EPS).
* The seed for platform keys is called the *Platform Primary Seed* (PPS).
* The seed for *Storage Root Key* (SRK) is called the *Storage Primary Seed* (SPS).

TPM 2.0 also introduces the *Null Seed*, which is set to a random value on every TPM reset.

The TPM 2.0 resources are referenced by handles.
Each handle is a 32-bit value.
Its most significant octet (8 bits) identifies the type of the referenced resource:

* ``MSO = 0x00``: PCR Handles
* ``MSO = 0x01``: Non-Volatile Index Handles (created by ``TPM2_NV_DefineSpace``)
* ``MSO = 0x02``: HMAC Session Handles (created when a session is started by ``TPM2_StartAuthSession``)
* ``MSO = 0x03``: Policy Session Handles (created when a session is started by ``TPM2_StartAuthSession``)
* ``MSO = 0x40``: Permanent Resource Handles (like Owner, Platform and Endorsement hierarchy controls)
* ``MSO = 0x80``: Transient Object Handles (flushed from memory on any ``TPM2_Startup``)
* ``MSO = 0x81``: Persistent Object Handles (created from a transient object using ``TPM2_EvictControl``)

Each resource also have a *name*, which is either the handle (for ``MSO = 0x00, 0x02, 0x03, 0x40``) or the hash digest of the public data associated with the resource, prefixed by the name of the hash algorithm (for ``MSO = 0x01, 0x80, 0x81``).

In TPM 2.0, quoting PCRs (i.e. signing them to attest their values) use an *Attestation Key* (AK), which is the successor of TPM 1.2's AIK.

  - This is described more thoroughly (as well as restricted keys, which can only sign data coming from the TPM) in https://developers.tpm.dev/posts/10242712.
  - An AK is linked to an EK.

Software Stack
--------------

There are several components for the software stack, that are described in https://tpm2-software.github.io/:

* Command-Line Interface tools, OpenSSL Engine, etc.
* TSS (TPM Software Stack): the main library
* TAB (TPM Access Broker)

  - TAB/RM (TPM Access Broker Resource Manager): user-space resource manager
  - tpm2-abrmd (TPM Access Broker Resource Manager Daemon): the service implementing TAB/RM

* TCTI (TPM Command Transmission Interface): commands with the TPM

  - Specified in https://trustedcomputinggroup.org/resource/tss-tcti-specification/ (TCG TSS 2.0 TPM Command Transmission Interface (TCTI) API Specification)

* UEFI or Kernel Driver (``/dev/tpm0`` or ``/dev/tpmrm0`` on Linux, for kernel-space resource manager)
* TPM hardware

The commands use several API (Application Programming Interface):

* SAPI (TSS 2.0 System API): this layer is intended to sit on top of the TCTI providing marshaling/unmarshalling for TPM commands and responses.
* ESAPI (TSS 2.0 Enhanced System API): this layer is intended to sit on top of the System API providing enhanced context management and cryptography.
* FAPI (TSS 2.0 Feature API): this layer sits above the ESAPI and provides a highlevel interface including a policy definition language and key store.

Simulator with vTPM
~~~~~~~~~~~~~~~~~~~

On a system without a TPM, it is possible to add a virtual one by using the module `tpm_vtpm_proxy` (since Linux 4.8) and the project `swtpm` (https://github.com/stefanberger/swtpm), with the following configuration for systemd:

.. code-block:: sh

    echo tpm_vtpm_proxy > /etc/modules-load.d/virtual-tpm.conf
    mkdir /var/lib/swtpm
    cat > /etc/systemd/system/swtpm.service << EOF
    [Unit]
    # Require modprobe tpm_vtpm_proxy
    ConditionPathExists=/dev/vtpmx
    Description=Software TPM

    [Service]
    Type=simple
    ExecStart=/usr/bin/swtpm chardev --tpm2 --vtpm-proxy --tpmstate dir=/var/lib/swtpm

    [Install]
    WantedBy=multi-user.target
    EOF

This creates devices `/dev/tpm0` and `/dev/tpmrm0`, usable in the same way as a hardware TPM.

Hardware interfaces with a TPM device
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

There are two different interfaces to TPM devices:

* TIS interface (TPM Interface Specification): for TPM 1

  - Uses LPC (Low Pin Count) or SPI (Serial Peripheral Interface) bus
  - Uses physical addresses ``0xfed4LXXX`` when ``L`` is the locality (0 to 4 ; 4 is specific to events only generated by hardware)
  - For example, seen as ``fed40000-fed44fff : MSFT0101:00`` in ``/proc/iomem``

* CRB (command/response buffer)

  - Uses ACPI table for TPM 2.0 to define registers (specification: https://trustedcomputinggroup.org/resource/tcg-acpi-specification/)

For example on a Dell Latitude E7440 laptop, the ACPI table contains a TCGA table for the TPM 1.2 eventlog::

    [000h 0000   4]                    Signature : "TCPA"    [Trusted Computing Platform Alliance table]
    [004h 0004   4]                 Table Length : 00000032
    [008h 0008   1]                     Revision : 02
    [009h 0009   1]                     Checksum : 61
    [00Ah 0010   6]                       Oem ID : "APTIO4"
    [010h 0016   8]                 Oem Table ID : "NAPAASF"
    [018h 0024   4]                 Oem Revision : 00000001
    [01Ch 0028   4]              Asl Compiler ID : "MSFT"
    [020h 0032   4]        Asl Compiler Revision : 01000013

    [024h 0036   2]               Platform Class : 0000
    [026h 0038   4]         Min Event Log Length : 00010000
    [02Ah 0042   8]            Event Log Address : 00000000DA7EE010

For example on a Levono T470 laptop, the ACPI table contains a TPM2 table::

    [000h 0000   4]                    Signature : "TPM2"    [Trusted Platform Module hardware interface table]
    [004h 0004   4]                 Table Length : 00000034
    [008h 0008   1]                     Revision : 03
    [009h 0009   1]                     Checksum : A8
    [00Ah 0010   6]                       Oem ID : "LENOVO"
    [010h 0016   8]                 Oem Table ID : "TP-N1Q  "
    [018h 0024   4]                 Oem Revision : 00001600
    [01Ch 0028   4]              Asl Compiler ID : "PTEC"
    [020h 0032   4]        Asl Compiler Revision : 00000002

    [024h 0036   4]                     Reserved : 00000000
    [028h 0040   8]              Control Address : 0000000000000000
        Physical address of the Control Area. The Control Area
        contains status registers and the location of the memory
        buffers for communicating with the device. The area may be
        in either TPM 2.0 device memory or in memory reserved by
        the system during boot. Interfaces that do not require the
        Control Area set this value to zero.
    [030h 0048   4]                 Start Method : 00000006
        The Start Method selector determines which mechanism the
        device driver uses to notify the TPM 2.0 device that a
        command is available for processing.
        2 = Uses the ACPI Start method
        6 = Reserved for the Memory mapped I/O Interface (TIS 1.2+Cancel)
        7 = Uses the Command Response Buffer Interface.
        8 = Uses the Command Response Buffer Interface with the ACPI Start Method.
        11 = Uses the Command Response Buffer Interface with ARM Secure Monitor Call (SMC)

There is also an entry related to the TPM in SSDT1.
This entry can be decoded using the TCG specification and source code such as https://https://github.com/tianocore/edk2/blob/edk2-stable202002/SecurityPkg/Tcg/Tcg2Smm/Tpm.asl

.. code-block:: c

    DefinitionBlock ("", "SSDT", 2, "LENOVO", "Tpm2Tabl", 0x00001000) {
        Scope (\_SB) {
            Device (TPM) {
                Name (_HID, "MSFT0101" /* TPM 2.0 Security Device */)  // _HID: Hardware ID
                Name (_STR, Unicode ("TPM 2.0 Device"))  // _STR: Description String
                Name (_CRS, ResourceTemplate () {  // _CRS: Current Resource Settings
                    Memory32Fixed (ReadOnly, 0xFED40000, 0x00005000)
                })

                // System Management Mode Interface port
                OperationRegion (SMIP, SystemIO, 0xB2, One)
                Field (SMIP, ByteAcc, NoLock, Preserve) { IOB2,   8 }

                // TPM region for TIS interface
                // /proc/iomem: fed40000-fed44fff : MSFT0101:00
                OperationRegion (TPMR, SystemMemory, 0xFED40000, 0x5000)
                Field (TPMR, AnyAcc, NoLock, Preserve) {
                    ACC0,   8 // TPM_ACCESS_0 (Used to gain ownership of the TPM for Locality 0)
                }

                // TPM Non-Volatile Storage
                // /proc/iomem: 9b52c000-9b599fff : ACPI Non-volatile Storage
                // Operational region for TPM support, TPM Physical Presence and TPM Memory Clear
                OperationRegion (TNVS, SystemMemory, 0x9B555000, 0x26)
                Field (TNVS, AnyAcc, NoLock, Preserve) {
                    PPIN,   8,  // Software SMI for Physical Presence Interface
                    PPIP,   32, // Used for save physical presence parameter
                    PPRP,   32, // Physical Presence request operation response
                    PPRQ,   32, // Physical Presence request operation
                    PPRM,   32, // Physical Presence request operation parameter
                    LPPR,   32, // Last Physical Presence request operation
                    FRET,   32, // Physical Presence function return code
                    MCIN,   8,  // Software SMI for Memory Clear Interface
                    MCIP,   32, // Used for save the Memory Overwrite Request parameter
                    MORD,   32, // Memory Overwrite Request Data
                    MRET,   32  // Memory Overwrite function return code
                }
                Method (PTS, 1, Serialized) { // PTS: Prepare To Sleep
                    // Detect Sx state for MOR, only S4, S5 need to handle
                    If (((Arg0 < 0x06) && (Arg0 > 0x03))) {
                        // Bit4 -- DisableAutoDetect. 0 -- Firmware MAY autodetect.
                        If (!(MORD & 0x10)) {
                            // Trigger the SMI through ACPI _PTS method.
                            MCIP = 0x02
                            IOB2 = MCIN /* \_SB_.TPM_.MCIN */
                        }
                    }
                    Return (Zero)
                }
                Method (_STA, 0, NotSerialized) {  // _STA: Status
                    If ((ACC0 == 0xFF)) { Return (Zero) } // Return "not present"
                    Return (0x0F) // Return "present|enabled|should be shown in the UI|functioning properly"
                }
                Method (HINF, 3, Serialized) { // Hardware Information
                    Switch (ToInteger (Arg1)) { // Arg1 is Revision ID
                        Case (Zero) { // Standard query, supports function 1-1
                            Return (Buffer (One) { 0x03 })
                        }
                        Case (One) {
                            Name (TPMV, Package (0x02) { // TPM Version
                                One,  // status of operation: success
                                Package (0x02) { 0x02, Zero } // TCG Revision implemented in security hardware: 2.0
                            })
                            If ((_STA () == Zero)) {
                                // return "status of operation: failure"
                                Return (Package (0x01) { Zero })
                            }
                            Return (TPMV) /* \_SB_.TPM_.HINF.TPMV */
                        }
                        Default { BreakPoint }
                    }
                    Return (Buffer (One) { 0x00 })
                }
                Name (TPM2, Package (0x02) { Zero, Zero })
                Name (TPM3, Package (0x03) { Zero, Zero, Zero })
                Method (TPPI, 3, Serialized) { // TCG Physical Presence Interface
                    Switch (ToInteger (Arg1)) {
                        Case (Zero) { // Standard query, supports function 1-8
                            Return (Buffer (0x02) { 0xFF, 0x01 })
                        }
                        Case (One) { // a) Get Physical Presence Interface Version
                            // TCG_ACPI_FUNCTION_GET_PHYSICAL_PRESENCE_INTERFACE_VERSION
                            Return ("1.3")
                        }
                        Case (0x02) { // b) Submit TPM Operation Request to Pre-OS Environment
                            // TCG_ACPI_FUNCTION_SUBMIT_REQUEST_TO_BIOS
                            PPRQ = DerefOf (Arg2 [Zero])
                            PPIP = 0x02
                            IOB2 = PPIN /* \_SB_.TPM_.PPIN */
                            Return (FRET) /* \_SB_.TPM_.FRET */
                        }
                        Case (0x03) { // c) Get Pending TPM Operation Requested By the OS
                            // TCG_ACPI_FUNCTION_GET_PENDING_REQUEST_BY_OS
                            TPM2 [One] = PPRQ /* \_SB_.TPM_.PPRQ */
                            Return (TPM2) /* \_SB_.TPM_.TPM2 */
                        }
                        Case (0x04) { // d) Get Platform-Specific Action to Transition to Pre-OS Environment
                            // TCG_ACPI_FUNCTION_GET_PLATFORM_ACTION_TO_TRANSITION_TO_BIOS
                            Return (0x02)
                        }
                        Case (0x05) { // e) Return TPM Operation Response to OS Environment
                            // TCG_ACPI_FUNCTION_RETURN_REQUEST_RESPONSE_TO_OS
                            PPIP = 0x05
                            IOB2 = PPIN /* \_SB_.TPM_.PPIN */
                            TPM3 [One] = LPPR /* \_SB_.TPM_.LPPR */
                            TPM3 [0x02] = PPRP /* \_SB_.TPM_.PPRP */
                            Return (TPM3) /* \_SB_.TPM_.TPM3 */
                        }
                        Case (0x06) { // f) Submit preferred user language (Not implemented)
                            // TCG_ACPI_FUNCTION_SUBMIT_PREFERRED_USER_LANGUAGE
                            Return (0x03)
                        }
                        Case (0x07) { // g) Submit TPM Operation Request to Pre-OS Environment 2
                            // TCG_ACPI_FUNCTION_SUBMIT_REQUEST_TO_BIOS_2
                            PPIP = 0x07
                            PPRQ = DerefOf (Arg2 [Zero])
                            PPRM = Zero
                            If ((PPRQ == 0x17)) {
                                PPRM = DerefOf (Arg2 [One])
                            }
                            IOB2 = PPIN /* \_SB_.TPM_.PPIN */
                            Return (FRET) /* \_SB_.TPM_.FRET */
                        }
                        Case (0x08) { // e) Get User Confirmation Status for Operation
                            // TCG_ACPI_FUNCTION_GET_USER_CONFIRMATION_STATUS_FOR_REQUEST
                            PPIP = 0x08
                            PPRQ = DerefOf (Arg2 [Zero])
                            IOB2 = PPIN /* \_SB_.TPM_.PPIN */
                            PPRQ = Zero
                            Return (FRET) /* \_SB_.TPM_.FRET */
                        }
                        Default { BreakPoint }
                    }
                    Return (One)
                }
                Method (TMCI, 3, Serialized) { // TCG Memory Clear Interface
                    Switch (ToInteger (Arg1)) {
                        Case (Zero) { // Standard query, supports function 1-1
                            Return (Buffer (One) { 0x03 })
                        }
                        Case (One) {
                            // Save the Operation Value of the Request to MORD (reserved memory)
                            MORD = DerefOf (Arg2 [Zero])
                            MCIP = One
                            IOB2 = MCIN /* \_SB_.TPM_.MCIN */
                            Return (MRET) /* \_SB_.TPM_.MRET */
                        }
                        Default { BreakPoint }
                    }
                    Return (One)
                }
                Method (_DSM, 4, Serialized) { // _DSM: Device-Specific Method
                    If ((Arg0 == ToUUID ("cf8e16a5-c1e8-4e25-b712-4f54a96702c8"))) {
                        // UUID for TCG Hardware Information
                        Return (HINF (Arg1, Arg2, Arg3))
                    }
                    If ((Arg0 == ToUUID ("3dddfaa6-361b-4eb4-a424-8d10089d1653"))) {
                        // UUID for TCG Physical Presence Interface
                        Return (TPPI (Arg1, Arg2, Arg3))
                    }
                    If ((Arg0 == ToUUID ("376054ed-cc13-4675-901c-4756d7f2d45d"))) {
                        // UUID for TCG Memory Clear Interface
                        Return (TMCI (Arg1, Arg2, Arg3))
                    }
                    Return (Buffer (One) { 0x00 })
                }
            }
        }
    }
