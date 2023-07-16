#!/usr/bin/env python3
# -*- coding:UTF-8 -*-
# Copyright (c) 2021 Nicolas Iooss
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
"""Compute TPM 2.0 E/A policy digests

TPM 2.0 enables using Enhanced Authorization (or Extended Authorization)
Policies to control the access of an object. It is possible to compute digests
through tpm-tools commands. For example:

    tpm2_startauthsession -S session.ctx
    tpm2_policypcr -S session.ctx -L policy.pcr0123 -l sha256:0,1,2,3
    tpm2_flushcontext session.ctx

Results in 84b506c91f205e06abd6f83f269d8d8011d495e09214a40fe32b4660301dda09
(in hex) in policy.pcr, which is the SHA256 digest of the command of the PCR
(using empty PCRs/zeros, for demos purpose).

Another example, to use endorsment hierarchy authentication:

    tpm2_startauthsession -S session.ctx
    tpm2_policysecret -S session.ctx -c e -L policy.secret
    tpm2_flushcontext session.ctx

This results in 837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa.

The computation of the digests is publicly documented, but no database of
well-known TPM 2.0 E/A policies seem to exist. This script aims at documenting
this using Python.

Documentation:

* https://www.youtube.com/watch?v=JckONn4h6pQ
  Introducing TPM NV Storage with E/A Policies and TSS-FAPI
  (Andreas Fuchs, Fraunhofer SIT, Linux Security Europe 2020)
* https://github.com/stefanberger/libtpms/blob/1ddf6450aaa10afb439f769a0bf61f49a3257865/src/tpm2/EACommands.c
  libtpms simulator implementation
* https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-3-Commands-01.38.pdf
  Trusted Platform Module Library, Part 3: Commands
    Family 2.0 Level 00 Revision 01.38 (September 29, 2016)
* https://trustedcomputinggroup.org/wp-content/uploads/TSS_JSON_Policy_v0p7_r08_pub.pdf
  TCG TSS 2.0 JSON Data Types and Policy Language Specification
    Version 0.7 Revision 08 (June 11, 2020)
"""
import binascii
import enum
import hashlib
import struct
import sys


@enum.unique
class Tpm20CommandCode(enum.IntEnum):
    """TPM_CC: command codes in TPM 2.0"""
    TPM2_CC_ACT_SetTimeout = 0x00000198
    TPM2_CC_AC_GetCapability = 0x00000194
    TPM2_CC_AC_Send = 0x00000195
    TPM2_CC_ActivateCredential = 0x00000147
    TPM2_CC_Certify = 0x00000148
    TPM2_CC_CertifyCreation = 0x0000014a
    TPM2_CC_CertifyX509 = 0x00000197
    TPM2_CC_ChangeEPS = 0x00000124
    TPM2_CC_ChangePPS = 0x00000125
    TPM2_CC_Clear = 0x00000126
    TPM2_CC_ClearControl = 0x00000127
    TPM2_CC_ClockRateAdjust = 0x00000130
    TPM2_CC_ClockSet = 0x00000128
    TPM2_CC_Commit = 0x0000018b
    TPM2_CC_ContextLoad = 0x00000161
    TPM2_CC_ContextSave = 0x00000162
    TPM2_CC_Create = 0x00000153
    TPM2_CC_CreateLoaded = 0x00000191
    TPM2_CC_CreatePrimary = 0x00000131
    TPM2_CC_DictionaryAttackLockReset = 0x00000139
    TPM2_CC_DictionaryAttackParameters = 0x0000013a
    TPM2_CC_Duplicate = 0x0000014b
    TPM2_CC_ECC_Decrypt = 0x0000019a
    TPM2_CC_ECC_Encrypt = 0x00000199
    TPM2_CC_ECC_Parameters = 0x00000178
    TPM2_CC_ECDH_KeyGen = 0x00000163
    TPM2_CC_ECDH_ZGen = 0x00000154
    TPM2_CC_EC_Ephemeral = 0x0000018e
    TPM2_CC_EncryptDecrypt = 0x00000164
    TPM2_CC_EncryptDecrypt2 = 0x00000193
    TPM2_CC_EventSequenceComplete = 0x00000185
    TPM2_CC_EvictControl = 0x00000120
    TPM2_CC_FieldUpgradeData = 0x00000141
    TPM2_CC_FieldUpgradeStart = 0x0000012f
    TPM2_CC_FirmwareRead = 0x00000179
    TPM2_CC_FlushContext = 0x00000165
    TPM2_CC_GetCapability = 0x0000017a
    TPM2_CC_GetCommandAuditDigest = 0x00000133
    TPM2_CC_GetRandom = 0x0000017b
    TPM2_CC_GetSessionAuditDigest = 0x0000014d
    TPM2_CC_GetTestResult = 0x0000017c
    TPM2_CC_GetTime = 0x0000014c
    TPM2_CC_HMAC = 0x00000155
    TPM2_CC_HMAC_Start = 0x0000015b
    TPM2_CC_Hash = 0x0000017d
    TPM2_CC_HashSequenceStart = 0x00000186
    TPM2_CC_HierarchyChangeAuth = 0x00000129
    TPM2_CC_HierarchyControl = 0x00000121
    TPM2_CC_Import = 0x00000156
    TPM2_CC_IncrementalSelfTest = 0x00000142
    TPM2_CC_Load = 0x00000157
    TPM2_CC_LoadExternal = 0x00000167
    TPM2_CC_MakeCredential = 0x00000168
    TPM2_CC_NV_Certify = 0x00000184
    TPM2_CC_NV_ChangeAuth = 0x0000013b
    TPM2_CC_NV_DefineSpace = 0x0000012a
    TPM2_CC_NV_Extend = 0x00000136
    TPM2_CC_NV_GlobalWriteLock = 0x00000132
    TPM2_CC_NV_Increment = 0x00000134
    TPM2_CC_NV_Read = 0x0000014e
    TPM2_CC_NV_ReadLock = 0x0000014f
    TPM2_CC_NV_ReadPublic = 0x00000169
    TPM2_CC_NV_SetBits = 0x00000135
    TPM2_CC_NV_UndefineSpace = 0x00000122
    TPM2_CC_NV_UndefineSpaceSpecial = 0x0000011f
    TPM2_CC_NV_Write = 0x00000137
    TPM2_CC_NV_WriteLock = 0x00000138
    TPM2_CC_ObjectChangeAuth = 0x00000150
    TPM2_CC_PCR_Allocate = 0x0000012b
    TPM2_CC_PCR_Event = 0x0000013c
    TPM2_CC_PCR_Extend = 0x00000182
    TPM2_CC_PCR_Read = 0x0000017e
    TPM2_CC_PCR_Reset = 0x0000013d
    TPM2_CC_PCR_SetAuthPolicy = 0x0000012c
    TPM2_CC_PCR_SetAuthValue = 0x00000183
    TPM2_CC_PP_Commands = 0x0000012d
    TPM2_CC_PolicyAuthValue = 0x0000016b
    TPM2_CC_PolicyAuthorize = 0x0000016a
    TPM2_CC_PolicyAuthorizeNV = 0x00000192
    TPM2_CC_PolicyCommandCode = 0x0000016c
    TPM2_CC_PolicyCounterTimer = 0x0000016d
    TPM2_CC_PolicyCpHash = 0x0000016e
    TPM2_CC_PolicyDuplicationSelect = 0x00000188
    TPM2_CC_PolicyGetDigest = 0x00000189
    TPM2_CC_PolicyLocality = 0x0000016f
    TPM2_CC_PolicyNV = 0x00000149
    TPM2_CC_PolicyNameHash = 0x00000170
    TPM2_CC_PolicyNvWritten = 0x0000018f
    TPM2_CC_PolicyOR = 0x00000171
    TPM2_CC_PolicyPCR = 0x0000017f
    TPM2_CC_PolicyPassword = 0x0000018c
    TPM2_CC_PolicyPhysicalPresence = 0x00000187
    TPM2_CC_PolicyRestart = 0x00000180
    TPM2_CC_PolicySecret = 0x00000151
    TPM2_CC_PolicySigned = 0x00000160
    TPM2_CC_PolicyTemplate = 0x00000190
    TPM2_CC_PolicyTicket = 0x00000172
    TPM2_CC_Policy_AC_SendSelect = 0x00000196
    TPM2_CC_Quote = 0x00000158
    TPM2_CC_RSA_Decrypt = 0x00000159
    TPM2_CC_RSA_Encrypt = 0x00000174
    TPM2_CC_ReadClock = 0x00000181
    TPM2_CC_ReadPublic = 0x00000173
    TPM2_CC_Rewrap = 0x00000152
    TPM2_CC_SelfTest = 0x00000143
    TPM2_CC_SequenceComplete = 0x0000013e
    TPM2_CC_SequenceUpdate = 0x0000015c
    TPM2_CC_SetAlgorithmSet = 0x0000013f
    TPM2_CC_SetCommandCodeAuditStatus = 0x00000140
    TPM2_CC_SetPrimaryPolicy = 0x0000012e
    TPM2_CC_Shutdown = 0x00000145
    TPM2_CC_Sign = 0x0000015d
    TPM2_CC_StartAuthSession = 0x00000176
    TPM2_CC_Startup = 0x00000144
    TPM2_CC_StirRandom = 0x00000146
    TPM2_CC_TestParms = 0x0000018a
    TPM2_CC_Unseal = 0x0000015e
    TPM2_CC_Vendor_TCG_Test = 0x20000000
    TPM2_CC_VerifySignature = 0x00000177
    TPM2_CC_ZGen_2Phase = 0x0000018d


@enum.unique
class Tpm20Handle(enum.IntEnum):
    """TPM_HANDLE / TPM_HC: Handles Values Constants in TPM 2.0

    The reference for this enumeration is located on
    https://github.com/fishilico/home-files/blob/master/bin/tpm-show
    """
    TPM_HC_PCR0 = 0x00000000
    TPM_HC_PCR1 = 0x00000001
    TPM_HC_PCR2 = 0x00000002
    TPM_HC_PCR3 = 0x00000003
    TPM_HC_PCR4 = 0x00000004
    TPM_HC_PCR5 = 0x00000005
    TPM_HC_PCR6 = 0x00000006
    TPM_HC_PCR7 = 0x00000007
    TPM_HC_PCR8 = 0x00000008
    TPM_HC_PCR9 = 0x00000009
    TPM_HC_PCR10 = 0x0000000a
    TPM_HC_PCR11 = 0x0000000b
    TPM_HC_PCR12 = 0x0000000c
    TPM_HC_PCR13 = 0x0000000d
    TPM_HC_PCR14 = 0x0000000e
    TPM_HC_PCR15 = 0x0000000f
    TPM_HC_PCR16 = 0x00000010
    TPM_HC_PCR17 = 0x00000011
    TPM_HC_PCR18 = 0x00000012
    TPM_HC_PCR19 = 0x00000013
    TPM_HC_PCR20 = 0x00000014
    TPM_HC_PCR21 = 0x00000015
    TPM_HC_PCR22 = 0x00000016
    TPM_HC_PCR23 = 0x00000017
    TPM_OLD_NV_INTEL_TXT_LAUNCH_POLICY = 0x01200001
    TPM_OLD_NV_INTEL_TXT_LAUNCH_ERROR = 0x01200002
    TPM_OLD_NV_INTEL_TXT_PLATFORM_OWNER = 0x01400001
    TPM_OLD_NV_INTEL_TXT_PLATFORM_SUPPLIER = 0x01800001
    TPM_OLD_NV_INTEL_TXT_LAUNCH_AUXILIARY = 0x01800003
    TPM_OLD_NV_INTEL_TXT_SGX_SVN = 0x01800004
    TPM_RESERVED_HANDLE_RSA2048_EK_CERT = 0x01c00002
    TPM_RESERVED_HANDLE_RSA2048_EK_NONCE = 0x01c00003
    TPM_RESERVED_HANDLE_RSA2048_EK_TEMPLATE = 0x01c00004
    TPM_RESERVED_HANDLE_ECCP256_EK_CERT = 0x01c0000a
    TPM_RESERVED_HANDLE_ECCP256_EK_NONCE = 0x01c0000b
    TPM_RESERVED_HANDLE_ECCP256_EK_TEMPLATE = 0x01c0000c
    TPM_RESERVED_HANDLE_EK_NV_POLICY_SHA256 = 0x01c07f01
    TPM_RESERVED_HANDLE_EK_NV_POLICY_SHA384 = 0x01c07f02
    TPM_RESERVED_HANDLE_EK_NV_POLICY_SHA512 = 0x01c07f03
    TPM_RESERVED_HANDLE_EK_NV_POLICY_SM3_256 = 0x01c07f04
    TPM_NV_INTEL_TXT_LAUNCH_AUXILIARY = 0x01c10102
    TPM_NV_INTEL_TXT_PLATFORM_SUPPLIER = 0x01c10103
    TPM_NV_INTEL_TXT_SGX_SVN = 0x01c10104
    TPM_NV_INTEL_TXT_PLATFORM_OWNER = 0x01c10106
    TPM_NV_INTEL_TXT_LAUNCH_POLICY = 0x01c10131
    TPM_NV_INTEL_TXT_LAUNCH_ERROR = 0x01c10132
    TPM_RESERVED_HANDLE_IDEVID_CERT = 0x01c90000
    TPM_RH_SRK = 0x40000000
    TPM_RH_OWNER = 0x40000001
    TPM_RH_REVOKE = 0x40000002
    TPM_RH_TRANSPORT = 0x40000003
    TPM_RH_OPERATOR = 0x40000004
    TPM_RH_ADMIN = 0x40000005
    TPM_RH_EK = 0x40000006
    TPM_RH_NULL = 0x40000007
    TPM_RH_UNASSIGNED = 0x40000008
    TPM_RS_PW = 0x40000009
    TPM_RH_LOCKOUT = 0x4000000a
    TPM_RH_ENDORSEMENT = 0x4000000b
    TPM_RH_PLATFORM = 0x4000000c
    TPM_RH_PLATFORM_NV = 0x4000000d
    TPM_RH_AUTH_00 = 0x40000010
    TPM_RH_AUTH_FF = 0x4000010f
    TPM_RH_ACT_0 = 0x40000110
    TPM_RH_ACT_1 = 0x40000111
    TPM_RH_ACT_2 = 0x40000112
    TPM_RH_ACT_3 = 0x40000113
    TPM_RH_ACT_4 = 0x40000114
    TPM_RH_ACT_5 = 0x40000115
    TPM_RH_ACT_6 = 0x40000116
    TPM_RH_ACT_7 = 0x40000117
    TPM_RH_ACT_8 = 0x40000118
    TPM_RH_ACT_9 = 0x40000119
    TPM_RH_ACT_A = 0x4000011a
    TPM_RH_ACT_B = 0x4000011b
    TPM_RH_ACT_C = 0x4000011c
    TPM_RH_ACT_D = 0x4000011d
    TPM_RH_ACT_E = 0x4000011e
    TPM_RH_ACT_F = 0x4000011f
    TPM_RESERVED_HANDLE_SRK_0 = 0x81000000
    TPM_RESERVED_HANDLE_SRK_1 = 0x81000001
    TPM_RESERVED_HANDLE_SRK_2 = 0x81000002
    TPM_RESERVED_HANDLE_SRK_3 = 0x81000003
    TPM_RESERVED_HANDLE_SRK_4 = 0x81000004
    TPM_RESERVED_HANDLE_EK = 0x81010001
    TPM_RESERVED_HANDLE_IDEVID_KEY = 0x81020000
    TPM_RESERVED_HANDLE_PLATFORM_KEY_0 = 0x81800000
    TPM_RESERVED_HANDLE_PLATFORM_KEY_1 = 0x81800001


@enum.unique
class Tpm20EaArithmeticOperands(enum.IntEnum):
    """TPM_EO constants

    https://github.com/tianocore/edk2/blob/edk2-stable202105/MdePkg/Include/IndustryStandard/Tpm20.h#L465-L478
    https://github.com/tpm2-software/tpm2-tss/blob/3.1.0/include/tss2/tss2_tpm2_types.h#L407-L420
    """
    TPM_EO_EQ = 0x0000
    TPM_EO_NEQ = 0x0001
    TPM_EO_SIGNED_GT = 0x0002
    TPM_EO_UNSIGNED_GT = 0x0003
    TPM_EO_SIGNED_LT = 0x0004
    TPM_EO_UNSIGNED_LT = 0x0005
    TPM_EO_SIGNED_GE = 0x0006
    TPM_EO_UNSIGNED_GE = 0x0007
    TPM_EO_SIGNED_LE = 0x0008
    TPM_EO_UNSIGNED_LE = 0x0009
    TPM_EO_BITSET = 0x000a
    TPM_EO_BITCLEAR = 0x000b


WELL_KNOWN_EA_POLICIES = {
    # tpm2_policypassword -S session.ctx -L policy
    '8fcd2169ab92694e0c633f1ab772842b8241bbc20288981fc7ac1eddc1fddb0e': 'PolicyAuthValue()',

    # tpm2_policycommandcode -S session.ctx -L policy TPM2_CC_NV_UndefineSpaceSpecial
    '1d2dc485e177ddd0a40a344913ceeb420caa093c42587d2e1b132b157ccb5db0': 'PolicyCommandCode(TPM2_CC_NV_UndefineSpaceSpecial)',  # noqa

    # tpm2_policylocality -S session.ctx -L policy 1
    'ddee6af14bf3c4e8127ced87bcf9a57e1c0c8ddb5e67735c8505f96f07b8dbb8': 'PolicyLocality(ONE)',
    '07039b45baf2cc169b0d84af7c53fd1622b033df0a5dcda66360aa99e54947cd': 'PolicyLocality(THREE, FOUR)',

    # tpm2_policynvwritten -S session.ctx -L policy 0
    '3c326323670e28ad37bd57f63b4cc34d26ab205ef22f275c58d47fab2485466e': 'PolicyNvWritten(NO)',
    # tpm2_policynvwritten -S session.ctx -L policy 1
    'f7887d158ae8d38be0ac5319f37a9e07618bf54885453c7a54ddb0c6a6193beb': 'PolicyNvWritten(YES)',

    # tpm2_policypcr -S session.ctx -L policy -l sha256:0,1,2,3  (the PCR being zero)
    '84b506c91f205e06abd6f83f269d8d8011d495e09214a40fe32b4660301dda09': 'PolicyPCR(0,1,2,3 ZEROS)',

    # Physical presence, not available in tpm2-tools
    '0d7c6747b1b9facbba03492097aa9d5af792e5efc07346e05f9daa8b3d9e13b5': 'PolicyPhysicalPresence()',

    # tpm2_policysecret -S session.ctx -L policy -c o
    '0d84f55daf6e43ac97966e62c9bb989d3397777d25c5f749868055d65394f952': 'PolicySecret(RH_OWNER)',
    # tpm2_policysecret -S session.ctx -L policy -c l
    'a0cab3762662675a14347a87504584a08e1002525d91371c3289224bea3ff4af': 'PolicySecret(RH_LOCKOUT)',
    # tpm2_policysecret -S session.ctx -L policy -c e
    # Policy for EK template in "B.3.3 Template L-1: RSA 2048 (Storage)" and
    # "B.3.4 Template L-2: ECC NIST P256 (Storage)" and
    # "B.5.3 Policy Index I-1: SHA256" and
    # "B.6.2 Computing PolicyA" of
    # https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_Credential_Profile_EK_V2.1_R13.pdf
    # (TCG EK Credential Profile For TPM Family 2.0; Level 0,
    # Specification Version 2.1, Revision 13, 10 December 2018)
    '837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa': 'PolicySecret(RH_ENDORSEMENT)',
    '8bbf2266537c171cb56e403c4dc1d4b64f432611dc386e6f532050c3278c930e143e8bb1133824ccb431053871c6db53': 'PolicySecret_SHA384(RH_ENDORSEMENT)',  # noqa
    '1e3b76502c8a1425aa0b7b3fc646a1b0fae063b03b5368f9c4cddecaff0891dd682bac1a85d4d832b781ea451915de5fc5bf0dc4a1917cd42fa041e3f998e0ee': 'PolicySecret_SHA512(RH_ENDORSEMENT)',  # noqa
    # tpm2_policysecret -S session.ctx -L policy -c p
    'c8b1292eff2ce7a3fa0fb1aed9ad254fb03fc01c9abc2dd1985161ba6811bdc7': 'PolicySecret(RH_PLATFORM)',

    # Policy used by NV Index 0x01880001 by Windows, created by functions
    # TpmCore20::CreateWindowsNvBits2 (TpmW8ApiCreateOrVerifyWindowsNvBits20)
    # in TpmCoreProvisioning.dll (C:\Windows\System32\TpmCoreProvisioning.dll).
    # This index is in range 0x01800000-0x01bfffff "NV indexes defined by Owner".
    # It is used by functions TpmCore20::ReadWindowsNvBit2 (TpmW8ApiReadWindowsNvBit20)
    # and TpmCore20::SetWindowsNvBit2 (TpmW8ApiSetWindowsNvBit20).
    # - Bit 0 is used by TpmCoreProvisioning.dll to define the "Legacy DA Parameters bit" (DA = Dictionary Attack)
    # - Bit 1 is used by C:\Windows\System32\tcblaunch.exe to lock the NV Index 0x01880002 ("DRTM SVN")
    #     tpm2_nvreadpublic 0x01880001
    #     0x1880001:
    #       name: 000bd5e41629f4d1ee7b318d4a3e7eae93b0d11e72ffe71e5478f11461c49fa2e6f2
    #       hash algorithm:
    #         friendly: sha256
    #         value: 0xB
    #       attributes:
    #         friendly: policywrite|nt=0x1|writeall|ownerread|authread|written
    #         value: 0x28100620
    #       size: 8
    #       authorization policy: 0C8DF0CF0169C38828C8FA4C0FF37A548C23C041AEECD2A12CA740D501D620B7
    '0c8df0cf0169c38828c8fa4c0ff37a548c23c041aeecd2a12ca740d501d620b7': 'PolicySecret(RH_LOCKOUT) OR PolicyNvWritten(YES)',  # noqa

    # Policy documented in B.5. Policy NV Indices,
    # B.6.4 Computing PolicyC and B.6.5 Computing PolicyB
    # https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_Credential_Profile_EK_V2.1_R13.pdf
    # (TCG EK Credential Profile For TPM Family 2.0; Level 0,
    # Specification Version 2.1, Revision 13, 10 December 2018)
    '3767e2edd43ff45a3a7e1eaefcef78643dca964632e7aad82c673a30d8633fde': 'PolicyAuthorizeNV(0x01c07f01)',
    'd6032ce61f2fb3c240eb3cf6a33237ef2b6a16f4293c22b455e261cffd217ad5b4947c2d73e63005eed2dc2b3593d165': 'PolicyAuthorizeNV_SHA384(0x01c07f02)',  # noqa
    '589ee1e146544716e8deafe6db247b01b81e9f9c7dd16b814aa159138749105fba5388dd1dea702f35240c184933121e2c61b8f50d3ef91393a49a38c3f73fc8': 'PolicyAuthorizeNV_SHA512(0x01c07f03)',  # noqa
    'ca3d0a99a2b93906f7a3342414efcfb3a385d44cd1fd459089d19b5071c0b7a0': 'PolicySecret(RH_ENDORSEMENT) OR PolicyAuthorizeNV(0x01c07f01)',  # noqa
    'b26e7d28d11a50bc53d882bcf5fd3a1a074148bb35d3b4e4cb1c0ad9bde419cacb47ba09699646150f9fc000f3f80e12': 'PolicySecret_SHA384(RH_ENDORSEMENT) OR PolicyAuthorizeNV_SHA384(0x01c07f02)',  # noqa
    'b8221ca69e8550a4914de3faa6a18c072cc01208073a928d5d66d59ef79e49a429c41a6b269571d57edb25fbdb1838425608b413cd616a5f6db5b6071af99bea': 'PolicySecret_SHA512(RH_ENDORSEMENT) OR PolicyAuthorizeNV_SHA512(0x01c07f03)',  # noqa

    # Policy for Intel TXT Launch Auxiliary NV Index (0x01800003 or 0x01c10102)
    # with attributes "policywrite|policy_delete|write_stclear|authread|no_da|platformcreate"
    # documented in Appendix I of https://drive.google.com/file/d/1-vn6C-yPAR19xXILOE0FZ2-ARWbvr1t1/view
    # (Intel Trusted Execution Technology (Intel TXT), Software Development Guide,
    # Measured Launched Environment Developer's Guide, September 2019, Revision 016)
    # and in https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-system-guard/system-guard-secure-launch-and-smm-protection  # noqa
    # (System Guard Secure Launch and SMM protection)
    # and in https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-system-guard/how-hardware-based-root-of-trust-helps-protect-windows  # noqa
    # (Windows Defender System Guard: How a hardware-based root of trust helps protect Windows 10)
    '06c7d805ad3bec1106502a44c6b2e3b36d157750e8efca1fff998c874a7664c5': 'PolicyLocality(THREE, FOUR) AND PolicyCommandCode(TPM2_CC_NV_UndefineSpaceSpecial)',  # noqa
    'ef9a26fc22d1ae8cecff59e9481ac1ec533dbe228bec6d17930f4cb2cc5b9724': 'PolicyLocality(THREE, FOUR) OR (PolicyLocality(THREE, FOUR) AND PolicyCommandCode(TPM2_CC_NV_UndefineSpaceSpecial))',  # noqa

    # Policy for Intel TXT Launch Auxiliary NV Index (0x01800003 or 0x01c10102)
    # documented in Appendix J of https://usermanual.wiki/Document/inteltxtsoftwaredevelopmentguide.1721028921/view
    # (Intel Trusted Execution Technology (Intel TXT), Software Development Guide,
    # Measured Launched Environment Developer's Guide, August 2016, Revision 013)
    'dffdb6c8eafcbe691e358882b18703121eab40de2386f7a8e7b4a06591e1f0ee': '(PolicyLocality(THREE, FOUR) AND PolicyCommandCode(TPM2_CC_NV_Write)) OR (PolicyLocality(THREE, FOUR) AND PolicyCommandCode(TPM2_CC_NV_UndefineSpaceSpecial))',  # noqa

    # Policy for Microsoft TPM NV Index (0x01C101C0)
    # documented in https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-system-guard/how-hardware-based-root-of-trust-helps-protect-windows  # noqa
    # (Windows Defender System Guard: How a hardware-based root of trust helps protect Windows 10)
    # and https://github.com/MicrosoftDocs/windows-itpro-docs/blob/fecd3dbc321e9b702bf56fe2fe2c5bb03077a78a/windows/security/threat-protection/windows-defender-system-guard/how-hardware-based-root-of-trust-helps-protect-windows.md  # noqa
    'cb45c81ff34bcf0afb9e1a8029fa231c8727303c0922dcce684be3db817c20e1': 'PolicyAuthorize(MSFT_DRTM_AUTH_BLOB_SigningKey) OR (PolicyAuthorize(MSFT_DRTM_AUTH_BLOB_SigningKey) AND PolicyCommandCode(TPM2_CC_NV_UndefineSpaceSpecial))',  # noqa

    # Policy from tpm2-pkcs11 project:
    # https://github.com/tpm2-software/tpm2-pkcs11/blob/1.5.0/docs/tpm2-pkcs11_object_auth_model.md
    '98cbaba62e682c148a202acad533d9d63f85a68392fe1b66648d1c491aef1b3a': 'PolicyAuthValue() AND PolicyCommandCode(TPM2_CC_ObjectChangeAuth)',  # noqa
    '363ac945b6457c47c31f3355dba0db27de8db213d6250c6bf79685003f9fe7ab': 'PolicyAuthValue() AND PolicyCommandCode(TPM2_CC_NV_ChangeAuth)',  # noqa

    # Policy from "Write once, read many" example in https://youtu.be/JckONn4h6pQ?t=1698
    # tpm2_policycommandcode -S session.ctx -L policy.read TPM2_CC_NV_Read
    # tpm2_policynvwritten -S session.ctx -L policy.nvwritten_no 0
    # tpm2_policyor -S session.ctx -L policy -l sha256:policy.read,policy.nvwritten_no
    'a13eb52d274deb81431f5adc2e40f7e7c4094abba5d325da741e7afc4117901f': 'PolicyCommandCode(TPM2_CC_NV_Read) OR PolicyNvWritten(NO)',  # noqa

    # Policy from "Read for everyone, read with correct password" example in https://youtu.be/XwaSyHJIos8?t=1343
    # tpm2_policycommandcode -S session.ctx -L policy.read TPM2_CC_NV_Read
    # tpm2_policycommandcode -S session.ctx TPM2_CC_NV_Write
    # tpm2_policypassword -S session.ctx -L policy.write -L policy.write_AND_password
    # tpm2_policyor -S session.ctx -L policy -l sha256:policy.read,policy.write_AND_password
    '3355408f64a7ebe10ac90dab8a4405eef7c8f164eaa9034220c961edf1dbb680': 'PolicyCommandCode(TPM2_CC_NV_Write) AND PolicyAuthValue()',  # noqa
    'c1ef6962e6e15b2fda5026efca791ae9272bd87338c6fcacdf2ccca45d03d7be': 'PolicyCommandCode(TPM2_CC_NV_Read) OR (PolicyCommandCode(TPM2_CC_NV_Write) AND PolicyAuthValue())',  # noqa

    # Policy from tpm2_policycountertimer's man page
    # https://github.com/tpm2-software/tpm2-tools/blob/5.1/man/tpm2_policycountertimer.1.md
    # tpm2_policycountertimer -S session.ctx safe
    '310a0eb2a2c3ebd96c39d954d2865a80c7925ab8996c5d73d0bb723756ec42bf': 'PolicyCounterTimer(safe=YES)',
    # tpm2_policycountertimer -S session.ctx --ult 60000
    '7f48cceb9fae31e1662d7f8306fdd1c4f81d2b8d3b0e9d82fdec42949ad5257e': 'PolicyCounterTimer(time<60000)',
    # tpm2_policycountertimer -S session.ctx --ult clock=60000
    '47a3a4e8c7567b07e33aad03b2adca52b02c2f96cd0ea41073d67f3e3f80eaf8': 'PolicyCounterTimer(clock<60000)',
    # tpm2_policycountertimer -S session.ctx --ule resets=42
    'cd397212fec5f9c77c0f9eff5d6878d7d5d43fe0f0ef4bfd9c9edf2adc7ab30f': 'PolicyCounterTimer(resets<=42)',
    # tpm2_policycountertimer -S session.ctx --ule restarts=42
    '12d20ca971bf0eaafae3c58f4666013cab78654330ef8c95a3e7fc9d87c9658d': 'PolicyCounterTimer(restarts<=42)',

    # Policy generated by function WindowsAIK::GeneratePolicy in TpmCoreProvisioning.dll
    # (AIK = Attestation Identity Key)
    # tpm2_readpublic -c 0x81000002 :
    #   attributes:
    #     value: fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|sign
    #     raw: 0x50472
    #   authorization policy: 9dffcbf36c383ae699fb9868dc6dcb89d7153884be2803922c124158bfad22ae
    # Documentation: https://github.com/microsoft/TSS.MSR/blob/d715b5959f0ff211eef59669240af914bedd3dee/PCPTool.v11/dll/TPM20.cpp  # noqa
    # (function ValidateKeyAttest20)
    # tpm2_policycommandcode TPM2_CC_ObjectChangeAuth -S session.ctx && tpm2_policyauthvalue -S session.ctx
    # ("Explicit ADMIN policies")
    'e529f5d6112872954e8ed6605117b757e237c6e19513a949fee1f204c458023a': 'PolicyCommandCode(TPM2_CC_ObjectChangeAuth) AND PolicyAuthValue()',  # noqa
    # tpm2_policycommandcode TPM2_CC_Certify -S session.ctx && tpm2_policyauthvalue -S session.ctx
    # ("Legacy Auth Policy for TPC_CC_Certify for Windows 8.1")
    'af2ca569699c436a21006f1cb8a2756c98bc1c765a3559c5fe1c3f5e7228a7e7': 'PolicyCommandCode(TPM2_CC_Certify) AND PolicyAuthValue()',  # noqa
    # tpm2_policycommandcode TPM2_CC_ActivateCredential -S session.ctx && tpm2_policyauthvalue -S session.ctx
    'c413a847b11112b1cbddd4eca4daaa15a1852c1c3bba57461d257605f3d5af53': 'PolicyCommandCode(TPM2_CC_ActivateCredential) AND PolicyAuthValue()',  # noqa
    # tpm2_policycommandcode TPM2_CC_Certify -S session.ctx
    # ("Auth Policy for TPM_CC_Certify for Windows 10")
    '048e9a3ace08583f79f344ff785bbea9f07ac7fa3325b3d49a21dd5194c65850': 'PolicyCommandCode(TPM2_CC_Certify)',
    '9dffcbf36c383ae699fb9868dc6dcb89d7153884be2803922c124158bfad22ae': 'PolicyAuthValue() OR (PolicyCommandCode(TPM2_CC_ObjectChangeAuth) AND PolicyAuthValue()) OR (PolicyCommandCode(TPM2_CC_Certify) AND PolicyAuthValue()) OR (PolicyCommandCode(TPM2_CC_ActivateCredential) AND PolicyAuthValue()) OR PolicyCommandCode(TPM2_CC_Certify)',  # noqa

    # Policy generated by functions Tpm20SetDictionaryAttackParametersToLegacyMode and
    # Tpm2SetLockoutPolicy in TpmCoreProvisioning.dll, and stored in NV Index 0x01880011 by Windows
    # (It is used in SetPrimaryPolicy(TPM_RH_LOCKOUT, policy))
    #     tpm2_nvreadpublic 0x01880011
    #     0x1880011:
    #       name: 000b51a55522eb40aa7f66605334f0814377c886126edb72391675ec8132258398ad
    #       hash algorithm:
    #         friendly: sha256
    #         value: 0xB
    #       attributes:
    #         friendly: ownerwrite|authwrite|ownerread|authread|written
    #         value: 0x6000620
    #       size: 32
    #     tpm2_nvread 0x01880011 | xxd -p -c 32
    #     89d26cf200e9169047cfcb7a597b23e647f336a9a45c2aa09068cc370d2606f5
    # tpm2_policycommandcode TPM2_CC_Clear -S session.ctx
    'c4dfabceda8de836c95661952892b1def7203afb46fefec43ffcfc93be540730': 'PolicyCommandCode(TPM2_CC_Clear)',
    # echo 0c8df0cf0169c38828c8fa4c0ff37a548c23c041aeecd2a12ca740d501d620b7 | xxd -p -r > policy_for_0x01880001
    # tpm2_nvdefine --size=8 --attributes=0x61028 --policy=policy_for_0x01880001 0x01880001
    # tpm2_nvreadpublic 0x1880001
    # tpm2_startauthsession --policy-session -S session.ctx
    # tpm2_policysecret -S session.ctx -L policy_lockout -c l
    # echo f7887d158ae8d38be0ac5319f37a9e07618bf54885453c7a54ddb0c6a6193beb | xxd -p -r > policy_nvwritten_yes
    # tpm2_policyor -S session.ctx -l sha256:policy_lockout,policy_nvwritten_yes
    # tpm2_nvsetbits -S session.ctx --bits=0 0x1880001
    # => Does not work. Use https://github.com/tpm2-software/tpm2-pytss instead!
    #   pip install git+https://github.com/tpm2-software/tpm2-pytss
    #   python
    #     from tpm2_pytss import ESAPI, types
    #     ectx = ESAPI()
    #     auth = ectx.start_auth_session(
    #         tpm_key=types.ESYS_TR.NONE,
    #         bind=types.ESYS_TR.NONE,
    #         session_type=types.TPM2_SE.POLICY,
    #         symmetric=types.TPMT_SYM_DEF(algorithm=types.TPM2_ALG.NULL),
    #         auth_hash=types.TPM2_ALG.SHA256,
    #     )
    #     ectx.policy_secret(auth_handle=types.ESYS_TR.LOCKOUT, policy_session=auth,
    #         nonce_tpm=b"", cp_hash_a=b"", policy_ref=b"", expiration=0)
    #     ectx.policy_or(policy_session=auth, p_hash_list=types.TPML_DIGEST(digests=[
    #         bytes.fromhex("a0cab3762662675a14347a87504584a08e1002525d91371c3289224bea3ff4af"),
    #         bytes.fromhex("f7887d158ae8d38be0ac5319f37a9e07618bf54885453c7a54ddb0c6a6193beb")])
    #     print(str(ectx.policy_get_digest(policy_session=auth)))
    #     nv_tr = ectx.tr_from_tpmpublic(handle=0x1880001)
    #     ectx.nv_set_bits(nv_index=nv_tr, bits=0, auth_handle=nv_tr, session1=auth)
    # => so the index is written, now.
    # Now use tpm2_policynv!
    # echo '0000000000000001' | xxd -p -r | tpm2_policynv -S session.ctx -i- 0x01880001 bc
    'fca06036f1972d4d6069c625455d5c9f0d413f6c6b3bf5fd85314809dea99e8e': 'PolicyNV(windows_nvbits_0x01880001: bit 0 clear)',  # noqa
    '9711091a3aa56173f59b73b6d27d446fea52fd6fcefbc51bfa9271b09a206a87': 'PolicyNV(windows_nvbits_0x01880001: bit 0 clear->set)',  # noqa
    '268b6bac0debb1e5a1659d35f0d28421c9f62b8ea1a3326e9b71dd5ba295214a': 'PolicyNV(windows_nvbits_0x01880001: bit 0 clear->set) AND PolicyCpHash(TPM2_CC_DictionaryAttackParameters(RH_LOCKOUT,32,7200,86400))',  # noqa
    '89d26cf200e9169047cfcb7a597b23e647f336a9a45c2aa09068cc370d2606f5': 'PolicyCommandCode(TPM2_CC_Clear) OR (PolicyNV(windows_nvbits_0x01880001: bit 0 clear->set) AND PolicyCpHash(TPM2_CC_DictionaryAttackParameters(RH_LOCKOUT,32,7200,86400)))',  # noqa

    # Policy used by NV Index 0x01880002 by Windows, created by function
    # SvnpCheckCreateDrtmSvnIndex in tcblaunch.exe
    #     tpm2_nvreadpublic 0x01880002
    #       0x1880002:
    #         name: 000b56094638c94535195b5f577a5c007401de262ca8b90aeaa0433f8471ae5829f6
    #         hash algorithm:
    #           friendly: sha256
    #           value: 0xB
    #         attributes:
    #           friendly: policywrite|nt=0x1|writeall|ownerread|authread|no_da|written
    #           value: 0x28100622
    #         size: 8
    #         authorization policy: fb204f312abaaac0980ce9fbbf5260788c7c7b6d4b68b6ce0845750c761511ed
    '21784fe1fc7d5496c488e4fa33dd95f82fce48f440a75d882f8c8a44bc12018a': 'PolicyNV(windows_nvbits_0x01880001: bit 1 clear)',  # noqa
    '983d228d2827649da8e461587538d741991aef5cd1b5ceae869242f537535ce1': 'PolicyNvWritten(YES) AND PolicyLocality(TWO, THREE, FOUR)',  # noqa
    'fb204f312abaaac0980ce9fbbf5260788c7c7b6d4b68b6ce0845750c761511ed': 'PolicyNV(windows_nvbits_0x01880001: bit 1 clear) OR (PolicyNvWritten(YES) AND PolicyLocality(TWO, THREE, FOUR))',  # noqa

    # Coreboot policies used by some nvmem indexes
    # https://mail.coreboot.org/hyperkitty/list/coreboot-gerrit@coreboot.org/message/23XQ5J4IA2FYB4OUIR6KWRTMR3SGWYSD/
    # https://github.com/coreboot/coreboot/blob/4.14/src/security/vboot/secdata_tpm.c#L112
    # For index 0x01001007 (FIRMWARE_NV_INDEX)
    '093ceb41181d47808862d7946268ee6a17a10e3d1b79b32351bc56e4beaceff0': 'PolicyPCR(0 is ZEROS)',
    '4b44fc4192db5ad7167e0135708fd374890a06bfb56317df01f24f2226542a3f': 'PolicyCommandCode(TPM2_CC_NV_UndefineSpaceSpecial) AND PolicyPCR(0 is ZEROS)',  # noqa
    'cb5c8014e27a5f7586aae42db4f9776a977bcbc952ca61e33609da2b2c329418': 'PolicyCommandCode(TPM2_CC_NV_UndefineSpaceSpecial) AND PolicyPCR(0 is extended from SHA1(00,01,00))',  # noqa
    'e6ef4f0296ac3ef0f53906480985b1be8058e0e517e5f74a5b8a415efe339d87': 'PolicyCommandCode(TPM2_CC_NV_UndefineSpaceSpecial) AND PolicyPCR(0 is extended from SHA1(01,01,00))',  # noqa
    '44447900cbb83f5b15765650ef96980a2b966ea909044a01b85fa54a96fc5984': '(PolicyCommandCode(TPM2_CC_NV_UndefineSpaceSpecial) AND PolicyPCR(0 is ZEROS)) OR (PolicyCommandCode(TPM2_CC_NV_UndefineSpaceSpecial) AND PolicyPCR(0 is extended from SHA1(00,01,00))) OR (PolicyCommandCode(TPM2_CC_NV_UndefineSpaceSpecial) AND PolicyPCR(0 is extended from SHA1(01,01,00)))',  # noqa

    # Policy with secret, seen on some Lenovo laptops.
    # Intel TXT documentation states that the auth policy of these NV Indexes is "OEM policy"
    # tpm2_nvreadpublic 0x01c10103 : LCP Platform Supplier (Intel TXT "PS")
    #   attributes:
    #     friendly: authwrite|policydelete|writelocked|writedefine|authread|no_da|written|platformcreate
    #     value: 0x42C0462
    #   authorization policy: B75CE1946F78DF8BAA426918DB09318017E6B38D048C954E05C2C4F34BD44060
    # tpm2_nvreadpublic 0x01c10104 : SGX Software Version Number (Intel TXT "SGX SVN")
    #   attributes:
    #     friendly: authwrite|policydelete|authread|no_da|written|platformcreate
    #     value: 0x4040462
    #   authorization policy: B75CE1946F78DF8BAA426918DB09318017E6B38D048C954E05C2C4F34BD44060
    #
    # Found in CFL_WHL_CML_U_V1_V2_H_ACM_KIt_WW11_2020/Tools/System_Guard_PS2_TPM_Ref
    # ExampleSecret is 771CEB9D52438BB72009A316750DEA301A6A62ED3835A18ED9AF89F9EF36EBE4
    # ExamplePhSecretORSha256.pDef is 22030B7E0BB1F9D50657571EE2F7FCE1EB91990C8B8AE977FCB3F158B03EBA96
    # UnDefineSpaceSpecial.pDef is B75CE1946F78DF8BAA426918DB09318017E6B38D048C954E05C2C4F34BD44060
    # ExamplePsFinalOrSha256.pDef is C001C8000210D0FAA4F4F4F8A78EF4F8264E6F8555340D2F04180F8CF110FFDD
    '22030b7e0bb1f9d50657571ee2f7fce1eb91990c8b8ae977fcb3f158b03eba96': 'zeros OR 771CEB9D52438BB72009A316750DEA301A6A62ED3835A18ED9AF89F9EF36EBE4',  # noqa
    'b75ce1946f78df8baa426918db09318017e6b38d048c954e05c2c4f34bd44060': '(zeros OR 771CEB9D52438BB72009A316750DEA301A6A62ED3835A18ED9AF89F9EF36EBE4) AND PolicyCommandCode(TPM2_CC_NV_UndefineSpaceSpecial)',  # noqa
    'c001c8000210d0faa4f4f4f8a78ef4f8264e6f8555340d2f04180f8cf110ffdd': '((zeros OR 771CEB9D52438BB72009A316750DEA301A6A62ED3835A18ED9AF89F9EF36EBE4) AND PolicyCommandCode(TPM2_CC_NV_UndefineSpaceSpecial)) OR (zeros OR 771CEB9D52438BB72009A316750DEA301A6A62ED3835A18ED9AF89F9EF36EBE4) OR PolicyNvWritten(NO)',  # noqa

    # Found in CFL_WHL_CML_U_V1_V2_H_ACM_KIt_WW11_2020/Tools/System_Guard_PS2_TPM_Ref
    # DefaultPsFinalORSha256.pDef is 9F970E88340B836B768E682DB1BE76EC3F4284282FDDF64B05ACF8FD2699A71C
    'a4469af0287113e5d5eb95287d94bab42bd166a42dfa89fe91866e7034420805': 'FD516FA72051D00FA032B98DF1E2110A20C2766E49B5FB417621D5572601743A AND PolicyCommandCode(TPM2_CC_NV_UndefineSpaceSpecial)',  # noqa
    '9f970e88340b836b768e682db1be76ec3f4284282fddf64b05acf8fd2699a71c': '(FD516FA72051D00FA032B98DF1E2110A20C2766E49B5FB417621D5572601743A AND PolicyCommandCode(TPM2_CC_NV_UndefineSpaceSpecial)) OR FD516FA72051D00FA032B98DF1E2110A20C2766E49B5FB417621D5572601743A OR PolicyNvWritten(NO)',  # noqa

    # Found in CFL_WHL_CML_U_V1_V2_H_ACM_KIt_WW11_2020/Tools/System_Guard_PS2_TPM_Ref
    # OriginalDefaultPsFinalORSha256.pDef is 6CE3379D380001BD45B1F6B3DFFFF39A03CA61BFFB13FEAFC2F257196DF49FE4
    'a8652ea8a9787937bc33c4164b58f07f8378bbae396875293a626048b5955c4c': '061408869C564D49F631C981EA9C303AA0B126671532CBA86ABBEDC73B8A5692 AND PolicyCommandCode(TPM2_CC_NV_UndefineSpaceSpecial)',  # noqa
    '6ce3379d380001bd45b1f6b3dffff39a03ca61bffb13feafc2f257196df49fe4': '(061408869C564D49F631C981EA9C303AA0B126671532CBA86ABBEDC73B8A5692 AND PolicyCommandCode(TPM2_CC_NV_UndefineSpaceSpecial)) OR 061408869C564D49F631C981EA9C303AA0B126671532CBA86ABBEDC73B8A5692 OR PolicyNvWritten(NO)',  # noqa

    # Unknown policy seen on some Lenovo laptops.
    # Intel TXT documentation states that the auth policy of these NV Indexes is "OEM policy"
    # tpm2_nvreadpublic 0x01800001 : LCP Platform Supplier (Intel TXT "PS", old)
    #   attributes:
    #     friendly: authwrite|policydelete|writelocked|writedefine|authread|no_da|written|platformcreate
    #     value: 0x42C0462
    #   authorization policy: 1169A46A813A8CCDD0F3066785207BB9B67AFD3A6CD6DFE5C5AEE120867A96DF
    # tpm2_nvreadpublic 0x01800004 : SGX Software Version Number (Intel TXT "SGX SVN", old)
    #   attributes:
    #     friendly: authwrite|policydelete|authread|no_da|written|platformcreate
    #     value: 0x4040462
    #   authorization policy: 1169A46A813A8CCDD0F3066785207BB9B67AFD3A6CD6DFE5C5AEE120867A96DF
    '1169a46a813a8ccdd0f3066785207bb9b67afd3a6cd6dfe5c5aee120867a96df': 'Unknown (used by Intel TXT for LCP Platform Supplier and SGX SVN)',  # noqa
}


def policy_and(old_digest, policy, alg):
    """Combine an old digest (possibly all-zeros for the first one) with a policy"""
    if alg is None or alg == 'sha256':
        ctx = hashlib.sha256(old_digest or b'\x00' * 32)
    elif alg == 'sha384':
        ctx = hashlib.sha384(old_digest or b'\x00' * 48)
    elif alg == 'sha512':
        ctx = hashlib.sha512(old_digest or b'\x00' * 64)
    else:
        raise ValueError("Unsupported hash algorithm for policy {}".format(repr(alg)))
    ctx.update(policy)
    return ctx.digest()


def policy_or(policies, alg=None):
    """TPM2_CC_PolicyOR with a set of policies"""
    return policy_and(None, struct.pack('>I', Tpm20CommandCode.TPM2_CC_PolicyOR) + b''.join(policies), alg)


def policy_auth_value(parent=None, alg=None):
    """TPM2_CC_PolicyAuthValue"""
    return policy_and(parent, struct.pack('>I', Tpm20CommandCode.TPM2_CC_PolicyAuthValue), alg)


def policy_authorize_nv(nv_index_name, parent=None, alg=None):
    """TPM2_CC_PolicyAuthorizeNV with the name of a NV index"""
    return policy_and(parent, struct.pack('>I', Tpm20CommandCode.TPM2_CC_PolicyAuthorizeNV) + nv_index_name, alg)


def policy_command_code(command, parent=None, alg=None):
    """TPM2_CC_PolicyCommandCode with a command code"""
    return policy_and(parent, struct.pack('>II', Tpm20CommandCode.TPM2_CC_PolicyCommandCode, command), alg)


def policy_locality(locality_bits, parent=None, alg=None):
    """TPM2_CC_PolicyLocality with localities given as bits

    Locality Zero is 1, One is 2, Two is 4, Three is 8, Four is 0x10.
    For localities 32-254, the value is directly represented
    (there is no locality 5-31)

    Locality 0: Always open for general use
    Locality 1: Operating system
    Locality 2: System software (OS) in secure mode (after Intel TXT)
    Locality 3: Intel TXT Authenticated Code Module (ACM)
    Locality 4: Hardware (processor executing its microcode)
    """
    return policy_and(parent, struct.pack('>IB', Tpm20CommandCode.TPM2_CC_PolicyLocality, locality_bits), alg)


def policy_nv_written(written, parent=None, alg=None):
    """TPM2_CC_PolicyNvWritten with a boolean value"""
    return policy_and(parent, struct.pack('>IB', Tpm20CommandCode.TPM2_CC_PolicyNvWritten, 1 if written else 0), alg)


def policy_pcr(pcrs, parent=None, alg=None):
    """TPM2_CC_PolicyPCR with a dict of PCR index->value"""
    pcr_bitmap = bytearray(3)
    if alg is None or alg == 'sha256':
        pcr_digest = hashlib.sha256()
    else:
        raise ValueError("Unsupported hash algorithm for policy PCR: {}".format(repr(alg)))
    for pcr_index, pcr_value in sorted(pcrs.items()):
        assert 0 <= pcr_index < 24
        pcr_bitmap[pcr_index // 8] |= 1 << (pcr_index % 8)
        pcr_digest.update(pcr_value)
    # Marshal a TPML_PCR_SELECTION with one item
    # TPM_ALG_SHA256 = 0x000b
    pcr_selection = struct.pack('>IHB', 1, 0x000b, 3) + pcr_bitmap
    policy = struct.pack('>I', Tpm20CommandCode.TPM2_CC_PolicyPCR) + pcr_selection + pcr_digest.digest()
    return policy_and(parent, policy, alg)


def policy_physical_presence(parent=None, alg=None):
    """TPM2_CC_PolicyPhysicalPresence"""
    return policy_and(parent, struct.pack('>I', Tpm20CommandCode.TPM2_CC_PolicyPhysicalPresence), alg)


def policy_secret_by_handle(handle, parent=None, alg=None):
    """TPM2_CC_PolicySecret with a handle which is neither transient nor NV index
    (otherwise the object name is used in the computation)
    """
    policy = policy_and(parent, struct.pack('>II', Tpm20CommandCode.TPM2_CC_PolicySecret, handle), alg)
    # The "reference data" is always added to the policy hash, even when it is empty
    return policy_and(policy, b'', alg)


def policy_counter_timer(offset, operation, value, parent=None, alg=None):
    """TPM2_CC_PolicyCounterTimer with an integer offset, TPM_EO operation and encoded value"""
    # The specification defines a double-hash to compute the policy
    args = value + struct.pack('>HH', offset, operation)
    if alg is None or alg == 'sha256':
        hash_args = hashlib.sha256(args).digest()
    elif alg == 'sha384':
        hash_args = hashlib.sha384(args).digest()
    elif alg == 'sha512':
        hash_args = hashlib.sha512(args).digest()
    else:
        raise ValueError("Unsupported hash algorithm for policy {}".format(repr(alg)))
    return policy_and(parent, struct.pack('>I', Tpm20CommandCode.TPM2_CC_PolicyCounterTimer) + hash_args, alg)


def policy_counter_timer_time(operation, value, parent=None, alg=None):
    """TPM2_CC_PolicyCounterTimer with offset 0 of struct TPMS_TIME_INFO: UINT64 time"""
    return policy_counter_timer(0, operation, struct.pack('>Q', value), parent=parent, alg=alg)


def policy_counter_timer_clock(operation, value, parent=None, alg=None):
    """TPM2_CC_PolicyCounterTimer with offset 8 of struct TPMS_TIME_INFO: UINT64 clock"""
    return policy_counter_timer(8, operation, struct.pack('>Q', value), parent=parent, alg=alg)


def policy_counter_timer_resets(operation, value, parent=None, alg=None):
    """TPM2_CC_PolicyCounterTimer with offset 0x10 of struct TPMS_TIME_INFO: UINT32 resetCount"""
    return policy_counter_timer(0x10, operation, struct.pack('>I', value), parent=parent, alg=alg)


def policy_counter_timer_restarts(operation, value, parent=None, alg=None):
    """TPM2_CC_PolicyCounterTimer with offset 0x14 of struct TPMS_TIME_INFO: UINT32 restartCount"""
    return policy_counter_timer(0x14, operation, struct.pack('>I', value), parent=parent, alg=alg)


def policy_counter_timer_safe(operation=Tpm20EaArithmeticOperands.TPM_EO_EQ, value=1, parent=None, alg=None):
    """TPM2_CC_PolicyCounterTimer with offset 0x18 of struct TPMS_TIME_INFO: TPMI_YES_NO safe"""
    return policy_counter_timer(0x18, operation, struct.pack('B', value), parent=parent, alg=alg)


def compute_nv_name_sha256(nv_index, attributes, auth_policy, data_size):
    """Compute the name of an index using name_alg=SHA256"""
    base_name = (
        struct.pack('>IHIH', nv_index, 0x000b, attributes, len(auth_policy)) +
        auth_policy +
        struct.pack('>H', data_size))
    return struct.pack('>H', 0x000b) + hashlib.sha256(base_name).digest()


def policy_nv(nv_name, operandb, offset, operation, parent=None, alg=None):
    """TPM2_CC_PolicyNV with an operation to compare the data with some operand"""
    args = operandb + struct.pack('>HH', offset, operation)
    if alg is None or alg == 'sha256':
        hash_args = hashlib.sha256(args).digest()
    elif alg == 'sha384':
        hash_args = hashlib.sha384(args).digest()
    elif alg == 'sha512':
        hash_args = hashlib.sha512(args).digest()
    else:
        raise ValueError("Unsupported hash algorithm for policy {}".format(repr(alg)))
    return policy_and(parent, struct.pack('>I', Tpm20CommandCode.TPM2_CC_PolicyNV) + hash_args + nv_name, alg)


def policy_cphash(cphash, parent=None, alg=None):
    """TPM2_CC_PolicyCpHash with the hash of a command"""
    return policy_and(parent, struct.pack('>I', Tpm20CommandCode.TPM2_CC_PolicyCpHash) + cphash, alg)


def check_well_known_ea_policies():
    """Check the consistency of WELL_KNOWN_EA_POLICIES"""
    computed = {}
    computed['PolicyAuthValue()'] = policy_auth_value()
    computed['PolicyCommandCode(TPM2_CC_NV_UndefineSpaceSpecial)'] = policy_command_code(
        Tpm20CommandCode.TPM2_CC_NV_UndefineSpaceSpecial)
    computed['PolicyLocality(ONE)'] = policy_locality(1)
    computed['PolicyLocality(THREE, FOUR)'] = policy_locality(0x18)
    computed['PolicyNvWritten(NO)'] = policy_nv_written(False)
    computed['PolicyNvWritten(YES)'] = policy_nv_written(True)
    computed['PolicyPCR(0,1,2,3 ZEROS)'] = policy_pcr({
        0: b'\x00' * 32,
        1: b'\x00' * 32,
        2: b'\x00' * 32,
        3: b'\x00' * 32,
    })
    computed['PolicyPhysicalPresence()'] = policy_physical_presence()
    computed['PolicySecret(RH_OWNER)'] = policy_secret_by_handle(Tpm20Handle.TPM_RH_OWNER)
    computed['PolicySecret(RH_ENDORSEMENT)'] = policy_secret_by_handle(Tpm20Handle.TPM_RH_ENDORSEMENT)
    computed['PolicySecret_SHA384(RH_ENDORSEMENT)'] = policy_secret_by_handle(Tpm20Handle.TPM_RH_ENDORSEMENT, alg='sha384')  # noqa
    computed['PolicySecret_SHA512(RH_ENDORSEMENT)'] = policy_secret_by_handle(Tpm20Handle.TPM_RH_ENDORSEMENT, alg='sha512')  # noqa
    computed['PolicySecret(RH_LOCKOUT)'] = policy_secret_by_handle(Tpm20Handle.TPM_RH_LOCKOUT)
    computed['PolicySecret(RH_PLATFORM)'] = policy_secret_by_handle(Tpm20Handle.TPM_RH_PLATFORM)

    computed['PolicySecret(RH_LOCKOUT) OR PolicyNvWritten(YES)'] = policy_or((
        policy_secret_by_handle(Tpm20Handle.TPM_RH_LOCKOUT),
        policy_nv_written(True),
    ))

    # Follow section "B.6.3 Computing Policy Index Names" of
    # https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_Credential_Profile_EK_V2.1_R13.pdf
    i1_name = struct.pack('>H', 0x000b) + hashlib.sha256(
        struct.pack('>IHIH', 0x01c07f01, 0x000b, 0x220f1008, 0x0020) +
        policy_secret_by_handle(Tpm20Handle.TPM_RH_ENDORSEMENT, alg='sha256') +
        struct.pack('>H', 0x0022)).digest()
    assert i1_name == binascii.unhexlify('000b0c9d717e9c3fe69fda41769450bb145957f8b3610e084dbf65591a5d11ecd83f')
    computed['PolicyAuthorizeNV(0x01c07f01)'] = policy_authorize_nv(i1_name)
    computed['PolicySecret(RH_ENDORSEMENT) OR PolicyAuthorizeNV(0x01c07f01)'] = policy_or((
        policy_secret_by_handle(Tpm20Handle.TPM_RH_ENDORSEMENT),
        policy_authorize_nv(i1_name),
    ))
    i2_name = struct.pack('>H', 0x000c) + hashlib.sha384(
        struct.pack('>IHIH', 0x01c07f02, 0x000c, 0x220f1008, 0x0030) +
        policy_secret_by_handle(Tpm20Handle.TPM_RH_ENDORSEMENT, alg='sha384') +
        struct.pack('>H', 0x0032)).digest()
    assert i2_name == binascii.unhexlify('000cdb62fca346612c976732ff4e8621fb4e858be82586486504f7d02e621f8d7d61ae32cfc60c4d120609ed6768afcf090c')  # noqa
    computed['PolicyAuthorizeNV_SHA384(0x01c07f02)'] = policy_authorize_nv(i2_name, alg='sha384')
    computed['PolicySecret_SHA384(RH_ENDORSEMENT) OR PolicyAuthorizeNV_SHA384(0x01c07f02)'] = policy_or((
        policy_secret_by_handle(Tpm20Handle.TPM_RH_ENDORSEMENT, alg='sha384'),
        policy_authorize_nv(i2_name, alg='sha384'),
    ), alg='sha384')
    i3_name = struct.pack('>H', 0x000d) + hashlib.sha512(
        struct.pack('>IHIH', 0x01c07f03, 0x000d, 0x220f1008, 0x0040) +
        policy_secret_by_handle(Tpm20Handle.TPM_RH_ENDORSEMENT, alg='sha512') +
        struct.pack('>H', 0x0042)).digest()
    assert i3_name == binascii.unhexlify('000d1c47c0bbcbd3cf7d7cae6987d31937c171015dde3b7f0d3c869bca1f7e8a223b9acfadb49b7c9cf14d450f41e9327de34d9291eece2c58ab1dc10e9059cce560')  # noqa
    computed['PolicyAuthorizeNV_SHA512(0x01c07f03)'] = policy_authorize_nv(i3_name, alg='sha512')
    computed['PolicySecret_SHA512(RH_ENDORSEMENT) OR PolicyAuthorizeNV_SHA512(0x01c07f03)'] = policy_or((
        policy_secret_by_handle(Tpm20Handle.TPM_RH_ENDORSEMENT, alg='sha512'),
        policy_authorize_nv(i3_name, alg='sha512'),
    ), alg='sha512')

    computed['PolicyLocality(THREE, FOUR) AND PolicyCommandCode(TPM2_CC_NV_UndefineSpaceSpecial)'] = \
        policy_command_code(
            Tpm20CommandCode.TPM2_CC_NV_UndefineSpaceSpecial,
            policy_locality(0x18))
    computed['PolicyLocality(THREE, FOUR) OR (PolicyLocality(THREE, FOUR) AND PolicyCommandCode(TPM2_CC_NV_UndefineSpaceSpecial))'] = policy_or((  # noqa
        policy_locality(0x18),
        policy_command_code(
            Tpm20CommandCode.TPM2_CC_NV_UndefineSpaceSpecial,
            policy_locality(0x18)),
    ))
    computed['(PolicyLocality(THREE, FOUR) AND PolicyCommandCode(TPM2_CC_NV_Write)) OR (PolicyLocality(THREE, FOUR) AND PolicyCommandCode(TPM2_CC_NV_UndefineSpaceSpecial))'] = policy_or((  # noqa
        policy_command_code(
            Tpm20CommandCode.TPM2_CC_NV_Write,
            policy_locality(0x18)),
        policy_command_code(
            Tpm20CommandCode.TPM2_CC_NV_UndefineSpaceSpecial,
            policy_locality(0x18)),
    ))

    computed['PolicyAuthValue() AND PolicyCommandCode(TPM2_CC_ObjectChangeAuth)'] = \
        policy_command_code(
            Tpm20CommandCode.TPM2_CC_ObjectChangeAuth,
            policy_auth_value())
    computed['PolicyAuthValue() AND PolicyCommandCode(TPM2_CC_NV_ChangeAuth)'] = \
        policy_command_code(
            Tpm20CommandCode.TPM2_CC_NV_ChangeAuth,
            policy_auth_value())

    computed['PolicyCommandCode(TPM2_CC_NV_Read) OR PolicyNvWritten(NO)'] = policy_or((
        policy_command_code(Tpm20CommandCode.TPM2_CC_NV_Read),
        policy_nv_written(False),
    ))

    computed['PolicyCommandCode(TPM2_CC_NV_Write) AND PolicyAuthValue()'] = \
        policy_auth_value(policy_command_code(Tpm20CommandCode.TPM2_CC_NV_Write))
    computed['PolicyCommandCode(TPM2_CC_NV_Read) OR (PolicyCommandCode(TPM2_CC_NV_Write) AND PolicyAuthValue())'] = policy_or((  # noqa
        policy_command_code(Tpm20CommandCode.TPM2_CC_NV_Read),
        policy_auth_value(policy_command_code(Tpm20CommandCode.TPM2_CC_NV_Write)),
    ))

    computed['PolicyCounterTimer(safe=YES)'] = policy_counter_timer_safe()
    computed['PolicyCounterTimer(time<60000)'] = \
        policy_counter_timer_time(Tpm20EaArithmeticOperands.TPM_EO_UNSIGNED_LT, 60000)
    computed['PolicyCounterTimer(clock<60000)'] = \
        policy_counter_timer_clock(Tpm20EaArithmeticOperands.TPM_EO_UNSIGNED_LT, 60000)
    computed['PolicyCounterTimer(resets<=42)'] = \
        policy_counter_timer_resets(Tpm20EaArithmeticOperands.TPM_EO_UNSIGNED_LE, 42)
    computed['PolicyCounterTimer(restarts<=42)'] = \
        policy_counter_timer_restarts(Tpm20EaArithmeticOperands.TPM_EO_UNSIGNED_LE, 42)

    computed['PolicyCommandCode(TPM2_CC_ObjectChangeAuth) AND PolicyAuthValue()'] = \
        policy_auth_value(policy_command_code(Tpm20CommandCode.TPM2_CC_ObjectChangeAuth))
    computed['PolicyCommandCode(TPM2_CC_Certify) AND PolicyAuthValue()'] = \
        policy_auth_value(policy_command_code(Tpm20CommandCode.TPM2_CC_Certify))
    computed['PolicyCommandCode(TPM2_CC_ActivateCredential) AND PolicyAuthValue()'] = \
        policy_auth_value(policy_command_code(Tpm20CommandCode.TPM2_CC_ActivateCredential))
    computed['PolicyCommandCode(TPM2_CC_Certify)'] = policy_command_code(Tpm20CommandCode.TPM2_CC_Certify)
    computed['PolicyAuthValue() OR (PolicyCommandCode(TPM2_CC_ObjectChangeAuth) AND PolicyAuthValue()) OR (PolicyCommandCode(TPM2_CC_Certify) AND PolicyAuthValue()) OR (PolicyCommandCode(TPM2_CC_ActivateCredential) AND PolicyAuthValue()) OR PolicyCommandCode(TPM2_CC_Certify)'] = policy_or((  # noqa
        policy_auth_value(),
        policy_auth_value(policy_command_code(Tpm20CommandCode.TPM2_CC_ObjectChangeAuth)),
        policy_auth_value(policy_command_code(Tpm20CommandCode.TPM2_CC_Certify)),
        policy_auth_value(policy_command_code(Tpm20CommandCode.TPM2_CC_ActivateCredential)),
        policy_command_code(Tpm20CommandCode.TPM2_CC_Certify),
    ))

    computed['PolicyCommandCode(TPM2_CC_Clear)'] = policy_command_code(Tpm20CommandCode.TPM2_CC_Clear)
    windows_nvbits_0x01880001 = compute_nv_name_sha256(
        0x01880001, 0x20061028, computed['PolicySecret(RH_LOCKOUT) OR PolicyNvWritten(YES)'], 8)
    assert windows_nvbits_0x01880001 == binascii.unhexlify('000bd5e41629f4d1ee7b318d4a3e7eae93b0d11e72ffe71e5478f11461c49fa2e6f2')  # noqa
    computed['PolicyNV(windows_nvbits_0x01880001: bit 0 clear)'] = \
        policy_nv(windows_nvbits_0x01880001, struct.pack('>Q', 1), 0, Tpm20EaArithmeticOperands.TPM_EO_BITCLEAR)
    computed['PolicyNV(windows_nvbits_0x01880001: bit 0 clear->set)'] = \
        policy_nv(
            windows_nvbits_0x01880001, struct.pack('>Q', 1), 0, Tpm20EaArithmeticOperands.TPM_EO_BITSET,
            parent=policy_nv(
                windows_nvbits_0x01880001, struct.pack('>Q', 1), 0, Tpm20EaArithmeticOperands.TPM_EO_BITCLEAR,
            ),
        )
    cphash_dictattackparams = hashlib.sha256(struct.pack(
        '>IIIII',
        Tpm20CommandCode.TPM2_CC_DictionaryAttackParameters,
        Tpm20Handle.TPM_RH_LOCKOUT,
        32,  # newMaxTries
        7200,  # newRecoveryTime
        86400,  # lockoutRecovery
    )).digest()
    computed['PolicyNV(windows_nvbits_0x01880001: bit 0 clear->set) AND PolicyCpHash(TPM2_CC_DictionaryAttackParameters(RH_LOCKOUT,32,7200,86400))'] = (  # noqa
        policy_cphash(
            cphash_dictattackparams,
            parent=policy_nv(
                windows_nvbits_0x01880001, struct.pack('>Q', 1), 0, Tpm20EaArithmeticOperands.TPM_EO_BITSET,
                parent=policy_nv(
                    windows_nvbits_0x01880001, struct.pack('>Q', 1), 0, Tpm20EaArithmeticOperands.TPM_EO_BITCLEAR,
                ),
            ),
        )
    )
    computed['PolicyCommandCode(TPM2_CC_Clear) OR (PolicyNV(windows_nvbits_0x01880001: bit 0 clear->set) AND PolicyCpHash(TPM2_CC_DictionaryAttackParameters(RH_LOCKOUT,32,7200,86400)))'] = policy_or((  # noqa
        policy_command_code(Tpm20CommandCode.TPM2_CC_Clear),
        policy_cphash(
            cphash_dictattackparams,
            parent=policy_nv(
                windows_nvbits_0x01880001, struct.pack('>Q', 1), 0, Tpm20EaArithmeticOperands.TPM_EO_BITSET,
                parent=policy_nv(
                    windows_nvbits_0x01880001, struct.pack('>Q', 1), 0, Tpm20EaArithmeticOperands.TPM_EO_BITCLEAR,
                ),
            ),
        )
    ))

    assert windows_nvbits_0x01880001 == binascii.unhexlify('000bd5e41629f4d1ee7b318d4a3e7eae93b0d11e72ffe71e5478f11461c49fa2e6f2')  # noqa
    computed['PolicyNV(windows_nvbits_0x01880001: bit 1 clear)'] = \
        policy_nv(windows_nvbits_0x01880001, struct.pack('>Q', 2), 0, Tpm20EaArithmeticOperands.TPM_EO_BITCLEAR)
    computed['PolicyNvWritten(YES) AND PolicyLocality(TWO, THREE, FOUR)'] = \
        policy_locality(0x1c, policy_nv_written(True))
    computed['PolicyNV(windows_nvbits_0x01880001: bit 1 clear) OR (PolicyNvWritten(YES) AND PolicyLocality(TWO, THREE, FOUR))'] = policy_or((  # noqa
        policy_nv(windows_nvbits_0x01880001, struct.pack('>Q', 2), 0, Tpm20EaArithmeticOperands.TPM_EO_BITCLEAR),
        policy_locality(0x1c, policy_nv_written(True)),
    ))
    windows_drtm_svn_0x01880002 = compute_nv_name_sha256(
        0x01880002, 0x22061028, computed['PolicyNV(windows_nvbits_0x01880001: bit 1 clear) OR (PolicyNvWritten(YES) AND PolicyLocality(TWO, THREE, FOUR))'], 8)  # noqa
    assert windows_drtm_svn_0x01880002 == binascii.unhexlify('000b56094638c94535195b5f577a5c007401de262ca8b90aeaa0433f8471ae5829f6')  # noqa

    computed['PolicyPCR(0 is ZEROS)'] = policy_pcr({0: b'\x00' * 32})
    computed['PolicyCommandCode(TPM2_CC_NV_UndefineSpaceSpecial) AND PolicyPCR(0 is ZEROS)'] = policy_pcr(
        {0: b'\x00' * 32},
        policy_command_code(Tpm20CommandCode.TPM2_CC_NV_UndefineSpaceSpecial))
    computed['PolicyCommandCode(TPM2_CC_NV_UndefineSpaceSpecial) AND PolicyPCR(0 is extended from SHA1(00,01,00))'] = policy_pcr(  # noqa
        {0: hashlib.sha256(b'\x00' * 32 + hashlib.sha1(b'\x00\x01\x00').digest() + b'\x00' * 12).digest()},
        policy_command_code(Tpm20CommandCode.TPM2_CC_NV_UndefineSpaceSpecial))
    computed['PolicyCommandCode(TPM2_CC_NV_UndefineSpaceSpecial) AND PolicyPCR(0 is extended from SHA1(01,01,00))'] = policy_pcr(  # noqa
        {0: hashlib.sha256(b'\x00' * 32 + hashlib.sha1(b'\x01\x01\x00').digest() + b'\x00' * 12).digest()},
        policy_command_code(Tpm20CommandCode.TPM2_CC_NV_UndefineSpaceSpecial))
    computed['(PolicyCommandCode(TPM2_CC_NV_UndefineSpaceSpecial) AND PolicyPCR(0 is ZEROS)) OR (PolicyCommandCode(TPM2_CC_NV_UndefineSpaceSpecial) AND PolicyPCR(0 is extended from SHA1(00,01,00))) OR (PolicyCommandCode(TPM2_CC_NV_UndefineSpaceSpecial) AND PolicyPCR(0 is extended from SHA1(01,01,00)))'] = policy_or((  # noqa
        policy_pcr(
            {0: b'\x00' * 32},
            policy_command_code(Tpm20CommandCode.TPM2_CC_NV_UndefineSpaceSpecial)),
        policy_pcr(
            {0: hashlib.sha256(b'\x00' * 32 + hashlib.sha1(b'\x00\x01\x00').digest() + b'\x00' * 12).digest()},
            policy_command_code(Tpm20CommandCode.TPM2_CC_NV_UndefineSpaceSpecial)),
        policy_pcr(
            {0: hashlib.sha256(b'\x00' * 32 + hashlib.sha1(b'\x01\x01\x00').digest() + b'\x00' * 12).digest()},
            policy_command_code(Tpm20CommandCode.TPM2_CC_NV_UndefineSpaceSpecial)),
    ))

    computed['zeros OR 771CEB9D52438BB72009A316750DEA301A6A62ED3835A18ED9AF89F9EF36EBE4'] = policy_or((
        b'\x00' * 32,
        bytes.fromhex("771CEB9D52438BB72009A316750DEA301A6A62ED3835A18ED9AF89F9EF36EBE4"),
    ))
    computed['(zeros OR 771CEB9D52438BB72009A316750DEA301A6A62ED3835A18ED9AF89F9EF36EBE4) AND PolicyCommandCode(TPM2_CC_NV_UndefineSpaceSpecial)'] = policy_command_code(  # noqa
        Tpm20CommandCode.TPM2_CC_NV_UndefineSpaceSpecial,
        policy_or((
            b'\x00' * 32,
            bytes.fromhex("771CEB9D52438BB72009A316750DEA301A6A62ED3835A18ED9AF89F9EF36EBE4"),
        )),
    )
    computed['((zeros OR 771CEB9D52438BB72009A316750DEA301A6A62ED3835A18ED9AF89F9EF36EBE4) AND PolicyCommandCode(TPM2_CC_NV_UndefineSpaceSpecial)) OR (zeros OR 771CEB9D52438BB72009A316750DEA301A6A62ED3835A18ED9AF89F9EF36EBE4) OR PolicyNvWritten(NO)'] = policy_or((  # noqa
        policy_command_code(
            Tpm20CommandCode.TPM2_CC_NV_UndefineSpaceSpecial,
            policy_or((
                b'\x00' * 32,
                bytes.fromhex("771CEB9D52438BB72009A316750DEA301A6A62ED3835A18ED9AF89F9EF36EBE4"),
            )),
        ),
        policy_or((
            b'\x00' * 32,
            bytes.fromhex("771CEB9D52438BB72009A316750DEA301A6A62ED3835A18ED9AF89F9EF36EBE4"),
        )),
        policy_nv_written(False),
    ))
    computed['FD516FA72051D00FA032B98DF1E2110A20C2766E49B5FB417621D5572601743A AND PolicyCommandCode(TPM2_CC_NV_UndefineSpaceSpecial)'] =policy_command_code(  # noqa
        Tpm20CommandCode.TPM2_CC_NV_UndefineSpaceSpecial,
        bytes.fromhex("FD516FA72051D00FA032B98DF1E2110A20C2766E49B5FB417621D5572601743A"),
    )
    computed['(FD516FA72051D00FA032B98DF1E2110A20C2766E49B5FB417621D5572601743A AND PolicyCommandCode(TPM2_CC_NV_UndefineSpaceSpecial)) OR FD516FA72051D00FA032B98DF1E2110A20C2766E49B5FB417621D5572601743A OR PolicyNvWritten(NO)'] = policy_or((  # noqa
        policy_command_code(
            Tpm20CommandCode.TPM2_CC_NV_UndefineSpaceSpecial,
            bytes.fromhex("FD516FA72051D00FA032B98DF1E2110A20C2766E49B5FB417621D5572601743A"),
        ),
        bytes.fromhex("FD516FA72051D00FA032B98DF1E2110A20C2766E49B5FB417621D5572601743A"),
        policy_nv_written(False),
    ))
    computed['061408869C564D49F631C981EA9C303AA0B126671532CBA86ABBEDC73B8A5692 AND PolicyCommandCode(TPM2_CC_NV_UndefineSpaceSpecial)'] =policy_command_code(  # noqa
        Tpm20CommandCode.TPM2_CC_NV_UndefineSpaceSpecial,
        bytes.fromhex("061408869C564D49F631C981EA9C303AA0B126671532CBA86ABBEDC73B8A5692"),
    )
    computed['(061408869C564D49F631C981EA9C303AA0B126671532CBA86ABBEDC73B8A5692 AND PolicyCommandCode(TPM2_CC_NV_UndefineSpaceSpecial)) OR 061408869C564D49F631C981EA9C303AA0B126671532CBA86ABBEDC73B8A5692 OR PolicyNvWritten(NO)'] = policy_or((  # noqa
        policy_command_code(
            Tpm20CommandCode.TPM2_CC_NV_UndefineSpaceSpecial,
            bytes.fromhex("061408869C564D49F631C981EA9C303AA0B126671532CBA86ABBEDC73B8A5692"),
        ),
        bytes.fromhex("061408869C564D49F631C981EA9C303AA0B126671532CBA86ABBEDC73B8A5692"),
        policy_nv_written(False),
    ))

    # Hard-code the policy for Microsoft NV Index, as the signing key is not documented
    computed['PolicyAuthorize(MSFT_DRTM_AUTH_BLOB_SigningKey) OR (PolicyAuthorize(MSFT_DRTM_AUTH_BLOB_SigningKey) AND PolicyCommandCode(TPM2_CC_NV_UndefineSpaceSpecial))'] = bytes.fromhex(  # noqa
        'cb45c81ff34bcf0afb9e1a8029fa231c8727303c0922dcce684be3db817c20e1')

    # Compare the computed digests with the reference ones
    if sys.version_info < (3, 5):
        computed_set = frozenset((k, binascii.hexlify(v).decode('ascii')) for k, v in computed.items())
    else:
        computed_set = frozenset((k, v.hex()) for k, v in computed.items())
    reference_set = frozenset((v, k) for k, v in WELL_KNOWN_EA_POLICIES.items() if not v.startswith('Unknown '))
    unknown_computed = computed_set - reference_set
    if unknown_computed:
        print("Error: {} computed policies not in reference:".format(len(unknown_computed)))
        for name, policy in sorted(unknown_computed):
            print("- {}: {}".format(name, policy))
        raise RuntimeError("computed policies not in reference")

    unknown_reference = reference_set - computed_set
    if unknown_reference:
        print("Error: {} reference policies not in computed:".format(len(unknown_reference)))
        for name, policy in sorted(unknown_reference):
            print("- {}: {}".format(name, policy))
        raise RuntimeError("reference policies not in computed")

    assert computed_set == reference_set


if __name__ == '__main__':
    check_well_known_ea_policies()
    for digest, desc in sorted(WELL_KNOWN_EA_POLICIES.items()):
        print("{} = {}".format(digest, desc))
