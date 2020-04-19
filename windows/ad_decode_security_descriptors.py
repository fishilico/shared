#!/usr/bin/env python3
# -*- coding:UTF-8 -*-
# Copyright (c) 2020 Nicolas Iooss
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
"""Decode the security Descriptors from an Active Directory dumped with ORADAD

ORADAD: https://github.com/ANSSI-FR/ORADAD
"""
import argparse
import binascii
import collections
import ctypes
import enum
import logging
from pathlib import Path
import uuid
import re
import struct
import sys
from typing import Any, Callable, Dict, List, Mapping, NewType, Optional, Tuple

import attr


# pylint: disable=invalid-name
logger = logging.getLogger(__name__)


WELL_KNOWN_SIDS: Dict[str, Tuple[str, str]] = {
    'S-1-1-0': ('WD', 'World/Everyone'),
    'S-1-3-0': ('CO', 'Creator Owner'),
    'S-1-3-1': ('CG', 'Creator Group'),
    'S-1-5-2': ('NU', 'Network logon User'),
    'S-1-5-4': ('IU', 'Interactively logged-on User'),
    'S-1-5-6': ('SU', 'Service logon User'),
    'S-1-5-7': ('AN', 'Anonymous'),
    'S-1-5-9': ('ED', 'Enterprise Domain Controllers'),
    'S-1-5-10': ('PS', 'Principal Self'),
    'S-1-5-11': ('AU', 'Authenticated Users'),
    'S-1-5-12': ('RC', 'Restricted Code'),
    'S-1-5-18': ('SY', 'Local System'),
    'S-1-5-19': ('LS', 'Local Service'),
    'S-1-5-20': ('NS', 'Network Service'),
    'S-1-5-32-544': ('BA', 'Built-in Administrators'),
    'S-1-5-32-545': ('BU', 'Built-in Users'),
    'S-1-5-32-546': ('BG', 'Built-in Guests'),
    'S-1-5-32-547': ('PU', 'Built-in Power Users'),
    'S-1-5-32-548': ('AO', 'Built-in Account Operators'),
    'S-1-5-32-549': ('SO', 'Built-in System/Server Operators'),
    'S-1-5-32-550': ('PO', 'Built-in Printer Operators'),
    'S-1-5-32-551': ('BO', 'Built-in Backup Operators'),
    'S-1-5-32-552': ('RE', 'Built-in Replicator'),
    'S-1-5-32-554': ('RU', 'Built-in Pre Windows 2000 Compatible Access'),
    'S-1-5-32-555': ('RD', 'Built-in Remote Desktop Users'),
    'S-1-5-32-556': ('NO', 'Built-in Network Configuration Operators'),
    'S-1-5-32-558': ('MU', 'Built-in Performance Monitoring Users'),
    'S-1-5-32-574': ('CD', 'Built-in CertSVC (Certificate Service) DCOM Access Group'),

    'S-1-5-21-0-0-0-498': ('RO', 'Enterprise Read-Only Domain Controllers Group'),
    'S-1-5-21-0-0-0-500': ('LA', 'Local Administrator'),
    'S-1-5-21-0-0-0-501': ('LG', 'Local Guest'),
    'S-1-5-21-0-0-0-512': ('DA', 'Domain Admins'),
    'S-1-5-21-0-0-0-513': ('DU', 'Domain Users'),
    'S-1-5-21-0-0-0-514': ('DG', 'Domain Guests'),
    'S-1-5-21-0-0-0-515': ('DC', 'Domain Computers'),
    'S-1-5-21-0-0-0-516': ('DD', 'Domain Controllers'),
    'S-1-5-21-0-0-0-517': ('CA', 'Domain Certificate Publishers (Admins)'),
    'S-1-5-21-0-0-0-518': ('SA', 'Schema Administrators'),
    'S-1-5-21-0-0-0-519': ('EA', 'Entreprise Admins'),
    'S-1-5-21-0-0-0-520': ('PA', 'Group Policy Creator Owners (Admins)'),
    'S-1-5-21-0-0-0-553': ('RS', 'RAS (Remote Access Services) Servers'),
}

# Security identifiers local to the system
LOCAL_SIDS: Dict[str, str] = {}

# GUID from https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1522b774-6464-41a3-87a5-1e5633c3fbbb
CONTROL_ACCESS_RIGHTS_GUID: Dict[str, str] = {
    'ee914b82-0a98-11d1-adbb-00c04fd8d5cd': 'Abandon-Replication',
    '440820ad-65b4-11d1-a3da-0000f875ae0d': 'Add-GUID',
    '1abd7cf8-0a99-11d1-adbb-00c04fd8d5cd': 'Allocate-Rids',
    '68b1d179-0d15-4d4f-ab71-46152e79a7bc': 'Allowed-To-Authenticate',
    'edacfd8f-ffb3-11d1-b41d-00a0c968f939': 'Apply-Group-Policy',
    'a05b8cc2-17bc-4802-a710-e7c15ab866a2': 'Certificate-AutoEnrollment',
    '0e10c968-78fb-11d2-90d4-00c04f79dc55': 'Certificate-Enrollment',
    '014bf69c-7b3b-11d1-85f6-08002be74fab': 'Change-Domain-Master',  # or 'Change-Naming-Master'
    'cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd': 'Change-Infrastructure-Master',
    'bae50096-4752-11d1-9052-00c04fc2d4cf': 'Change-PDC',
    'd58d5f36-0a98-11d1-adbb-00c04fd8d5cd': 'Change-Rid-Master',
    'e12b56b6-0a95-11d1-adbb-00c04fd8d5cd': 'Change-Schema-Master',
    'e2a36dc9-ae17-47c3-b58b-be34c55ba633': 'Create-Inbound-Forest-Trust',
    '72e39547-7b18-11d1-adef-00c04fd8d5cd': 'DNS-Host-Name-Attributes',
    'fec364e0-0a98-11d1-adbb-00c04fd8d5cd': 'Do-Garbage-Collection',
    'ab721a52-1e2f-11d0-9819-00aa0040529b': 'Domain-Administer-Server',
    'b8119fd0-04f6-4762-ab7a-4986c76b3f9a': 'Domain-Other-Parameters',
    'c7407360-20bf-11d0-a768-00aa006e0529': 'Domain-Password',
    '88a9933e-e5c8-4f2a-9dd7-2527416b8092': 'DS-Bypass-Quota',
    '69ae6200-7f46-11d2-b9ad-00c04f79f805': 'DS-Check-Stale-Phantoms',
    '3e0f7e18-2c7a-4c10-ba82-4d926db99a3e': 'DS-Clone-Domain-Controller',
    '2f16c4a5-b98e-432c-952a-cb388ba33f2e': 'DS-Execute-Intentions-Script',
    '9923a32a-3607-11d2-b9be-0000f87a36b2': 'DS-Install-Replica',
    '4ecc03fe-ffc0-4947-b630-eb672a8a9dbc': 'DS-Query-Self-Quota',
    '084c93a2-620d-4879-a836-f0ae47de0e89': 'DS-Read-Partition-Secrets',
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2': 'DS-Replication-Get-Changes',
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2': 'DS-Replication-Get-Changes-All',
    '89e95b76-444d-4c62-991a-0facbeda640c': 'DS-Replication-Get-Changes-In-Filtered-Set',
    '1131f6ac-9c07-11d1-f79f-00c04fc2dcd2': 'DS-Replication-Manage-Topology',
    'f98340fb-7c5b-4cdb-a00b-2ebdfa115a96': 'DS-Replication-Monitor-Topology',
    '1131f6ab-9c07-11d1-f79f-00c04fc2dcd2': 'DS-Replication-Synchronize',
    '4125c71f-7fac-4ff0-bcb7-f09a41325286': 'DS-Set-Owner',
    '9b026da6-0d3c-465c-8bee-5199d7165cba': 'DS-Validated-Write-Computer',
    '94825a8d-b171-4116-8146-1e34d8f54401': 'DS-Write-Partition-Secrets',
    'e45795b2-9455-11d1-aebd-0000f80367c1': 'Email-Information',
    '05c74c5e-4deb-43b4-bd9f-86664c2a7fd5': 'Enable-Per-User-Reversibly-Encrypted-Password',
    '59ba2f42-79a2-11d0-9020-00c04fc2d3cf': 'General-Information',
    'b7b1b3de-ab09-4242-9e30-9980e5d322f7': 'Generate-RSoP-Logging',
    'b7b1b3dd-ab09-4242-9e30-9980e5d322f7': 'Generate-RSoP-Planning',
    '7c0e2a7c-a419-48e4-a995-10180aad54dd': 'Manage-Optional-Features',
    'bc0ac240-79a9-11d0-9020-00c04fc2d4cf': 'Membership',
    'ba33815a-4f93-4c76-87f3-57574bff8109': 'Migrate-SID-History',
    'b4e60130-df3f-11d1-9c86-006008764d0e': 'msmq-Open-Connector',
    '06bd3201-df3e-11d1-9c86-006008764d0e': 'msmq-Peek',
    '4b6e08c3-df3c-11d1-9c86-006008764d0e': 'msmq-Peek-computer-Journal',
    '4b6e08c1-df3c-11d1-9c86-006008764d0e': 'msmq-Peek-Dead-Letter',
    '06bd3200-df3e-11d1-9c86-006008764d0e': 'msmq-Receive',
    '4b6e08c2-df3c-11d1-9c86-006008764d0e': 'msmq-Receive-computer-Journal',
    '4b6e08c0-df3c-11d1-9c86-006008764d0e': 'msmq-Receive-Dead-Letter',
    '06bd3203-df3e-11d1-9c86-006008764d0e': 'msmq-Receive-journal',
    '06bd3202-df3e-11d1-9c86-006008764d0e': 'msmq-Send',
    'ffa6f046-ca4b-4feb-b40d-04dfee722543': 'MS-TS-GatewayAccess',
    'a1990816-4298-11d1-ade2-00c04fd8d5cd': 'Open-Address-Book',
    '77b5b886-944a-11d1-aebd-0000f80367c1': 'Personal-Information',
    '91e647de-d96f-4b70-9557-d63ff4f3ccd8': 'Private-Information',
    'e48d0154-bcf8-11d1-8702-00c04fb96050': 'Public-Information',
    '037088f8-0ae1-11d2-b422-00a0c968f939': 'RAS-Information',
    '1131f6ae-9c07-11d1-f79f-00c04fc2dcd2': 'Read-Only-Replication-Secret-Synchronization',
    '45ec5156-db7e-47bb-b53f-dbeb2d03c40f': 'Reanimate-Tombstones',
    '0bc1554e-0a99-11d1-adbb-00c04fd8d5cd': 'Recalculate-Hierarchy',
    '62dd28a8-7f46-11d2-b9ad-00c04f79f805': 'Recalculate-Security-Inheritance',
    'ab721a56-1e2f-11d0-9819-00aa0040529b': 'Receive-As',
    '9432c620-033c-4db7-8b58-14ef6d0bf477': 'Refresh-Group-Cache',
    '1a60ea8d-58a6-4b20-bcdc-fb71eb8a9ff8': 'Reload-SSL-Certificate',
    '7726b9d5-a4b4-4288-a6b2-dce952e80a7f': 'Run-Protect-Admin-Groups-Task',
    '91d67418-0135-4acc-8d79-c08e857cfbec': 'SAM-Enumerate-Entire-Domain',
    'bf9679c0-0de6-11d0-a285-00aa003049e2': 'Self-Membership',
    'ab721a54-1e2f-11d0-9819-00aa0040529b': 'Send-As',
    'ab721a55-1e2f-11d0-9819-00aa0040529b': 'Send-To',
    '5805bc62-bdc9-4428-a5e2-856a0f4c185e': 'Terminal-Server-License-Server',
    'ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501': 'Unexpire-Password',
    '280f369c-67c7-438e-ae98-1d46f3c6f541': 'Update-Password-Not-Required-Bit',
    'be2bb760-7f46-11d2-b9ad-00c04f79f805': 'Update-Schema-Cache',
    '4c164200-20c0-11d0-a768-00aa006e0529': 'User-Account-Restrictions',
    'ab721a53-1e2f-11d0-9819-00aa0040529b': 'User-Change-Password',
    '00299570-246d-11d0-a768-00aa006e0529': 'User-Force-Change-Password',
    '5f202010-79a5-11d0-9020-00c04fc2d4cf': 'User-Logon',
    '80863791-dbe9-4eb8-837e-7f0ab55d9ac7': 'Validated-MS-DS-Additional-DNS-Host-Name',
    'd31a8757-2447-4545-8081-3bb610cacbf2': 'Validated-MS-DS-Behavior-Version',
    'f3a64788-5306-11d1-a9c5-0000f80367c1': 'Validated-SPN',
    'e45795b3-9455-11d1-aebd-0000f80367c1': 'Web-Information',
}


# GUID from https://docs.microsoft.com/en-us/windows/win32/adschema/attributes-all
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-ada1/19528560-f41e-4623-a406-dabcfff0660f
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-ada2/e20ebc4e-5285-40ba-b3bd-ffcb81c2783e
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/4517e835-3ee6-44d4-bb95-a94b6966bfb0
ATTRIBUTES_BY_GUID: Dict[str, str] = {
    'bf967915-0de6-11d0-a285-00aa003049e2': 'Account-Expires',
    '031952ec-3b72-11d2-90cc-00c04fd91ab1': 'Account-Name-History',
    '7f56127d-5301-11d1-a9c5-0000f80367c1': 'ACS-Aggregate-Token-Rate-Per-User',
    '7f561283-5301-11d1-a9c5-0000f80367c1': 'ACS-Allocable-RSVP-Bandwidth',
    '1cb355a1-56d0-11d1-a9c6-0000f80367c1': 'ACS-Cache-Timeout',
    '7f56127a-5301-11d1-a9c5-0000f80367c1': 'ACS-Direction',
    '1cb355a0-56d0-11d1-a9c6-0000f80367c1': 'ACS-DSBM-DeadTime',
    '1cb3559e-56d0-11d1-a9c6-0000f80367c1': 'ACS-DSBM-Priority',
    '1cb3559f-56d0-11d1-a9c6-0000f80367c1': 'ACS-DSBM-Refresh',
    '7f561287-5301-11d1-a9c5-0000f80367c1': 'ACS-Enable-ACS-Service',
    'f072230e-aef5-11d1-bdcf-0000f80367c1': 'ACS-Enable-RSVP-Accounting',
    '7f561285-5301-11d1-a9c5-0000f80367c1': 'ACS-Enable-RSVP-Message-Logging',
    '7f561286-5301-11d1-a9c5-0000f80367c1': 'ACS-Event-Log-Level',
    'dab029b6-ddf7-11d1-90a5-00c04fd91ab1': 'ACS-Identity-Name',
    'f072230c-aef5-11d1-bdcf-0000f80367c1': 'ACS-Max-Aggregate-Peak-Rate-Per-User',
    '7f56127e-5301-11d1-a9c5-0000f80367c1': 'ACS-Max-Duration-Per-Flow',
    'f0722310-aef5-11d1-bdcf-0000f80367c1': 'ACS-Max-No-Of-Account-Files',
    '1cb3559c-56d0-11d1-a9c6-0000f80367c1': 'ACS-Max-No-Of-Log-Files',
    '7f561284-5301-11d1-a9c5-0000f80367c1': 'ACS-Max-Peak-Bandwidth',
    '7f56127c-5301-11d1-a9c5-0000f80367c1': 'ACS-Max-Peak-Bandwidth-Per-Flow',
    'f0722311-aef5-11d1-bdcf-0000f80367c1': 'ACS-Max-Size-Of-RSVP-Account-File',
    '1cb3559d-56d0-11d1-a9c6-0000f80367c1': 'ACS-Max-Size-Of-RSVP-Log-File',
    '81f6e0df-3b90-11d2-90cc-00c04fd91ab1': 'ACS-Max-Token-Bucket-Per-Flow',
    '7f56127b-5301-11d1-a9c5-0000f80367c1': 'ACS-Max-Token-Rate-Per-Flow',
    '87a2d8f9-3b90-11d2-90cc-00c04fd91ab1': 'ACS-Maximum-SDU-Size',
    '9c65329b-3b90-11d2-90cc-00c04fd91ab1': 'ACS-Minimum-Delay-Variation',
    '9517fefb-3b90-11d2-90cc-00c04fd91ab1': 'ACS-Minimum-Latency',
    '8d0e7195-3b90-11d2-90cc-00c04fd91ab1': 'ACS-Minimum-Policed-Size',
    'aec2cfe3-3b90-11d2-90cc-00c04fd91ab1': 'ACS-Non-Reserved-Max-SDU-Size',
    'b6873917-3b90-11d2-90cc-00c04fd91ab1': 'ACS-Non-Reserved-Min-Policed-Size',
    'a331a73f-3b90-11d2-90cc-00c04fd91ab1': 'ACS-Non-Reserved-Peak-Rate',
    'a916d7c9-3b90-11d2-90cc-00c04fd91ab1': 'ACS-Non-Reserved-Token-Size',
    '1cb355a2-56d0-11d1-a9c6-0000f80367c1': 'ACS-Non-Reserved-Tx-Limit',
    'f072230d-aef5-11d1-bdcf-0000f80367c1': 'ACS-Non-Reserved-Tx-Size',
    '7f561282-5301-11d1-a9c5-0000f80367c1': 'ACS-Permission-Bits',
    '1cb3559a-56d0-11d1-a9c6-0000f80367c1': 'ACS-Policy-Name',
    '7f561281-5301-11d1-a9c5-0000f80367c1': 'ACS-Priority',
    'f072230f-aef5-11d1-bdcf-0000f80367c1': 'ACS-RSVP-Account-Files-Location',
    '1cb3559b-56d0-11d1-a9c6-0000f80367c1': 'ACS-RSVP-Log-Files-Location',
    '7cbd59a5-3b90-11d2-90cc-00c04fd91ab1': 'ACS-Server-List',
    '7f56127f-5301-11d1-a9c5-0000f80367c1': 'ACS-Service-Type',
    '7f561279-5301-11d1-a9c5-0000f80367c1': 'ACS-Time-Of-Day',
    '7f561280-5301-11d1-a9c5-0000f80367c1': 'ACS-Total-No-Of-Flows',
    '6d05fb41-246b-11d0-a9c8-00aa006c33ed': 'Additional-Information',
    '032160be-9824-11d1-aec0-0000f80367c1': 'Additional-Trusted-Service-Names',
    'f0f8ff84-1191-11d0-a060-00aa006c33ed': 'Address',
    'f70b6e48-06f4-11d2-aa53-00c04fd7d83a': 'Address-Book-Roots',
    '508ca374-a511-4e4e-9f4f-856f61a6b7e4': 'Address-Book-Roots2',
    '5fd42461-1262-11d0-a060-00aa006c33ed': 'Address-Entry-Display-Table',
    '5fd42462-1262-11d0-a060-00aa006c33ed': 'Address-Entry-Display-Table-MSDOS',
    '16775781-47f3-11d1-a9c3-0000f80367c1': 'Address-Home',
    '5fd42463-1262-11d0-a060-00aa006c33ed': 'Address-Syntax',
    '5fd42464-1262-11d0-a060-00aa006c33ed': 'Address-Type',
    '553fd038-f32e-11d0-b0bc-00c04fd8dca6': 'Admin-Context-Menu',
    'bf967918-0de6-11d0-a285-00aa003049e2': 'Admin-Count',
    'bf967919-0de6-11d0-a285-00aa003049e2': 'Admin-Description',
    'bf96791a-0de6-11d0-a285-00aa003049e2': 'Admin-Display-Name',
    '18f9b67d-5ac6-4b3b-97db-d0a406afb7ba': 'Admin-Multiselect-Property-Pages',
    '52458038-ca6a-11d0-afff-0000f80367c1': 'Admin-Property-Pages',
    '9a7ad940-ca53-11d1-bbd0-0080c76670c0': 'Allowed-Attributes',
    '9a7ad941-ca53-11d1-bbd0-0080c76670c0': 'Allowed-Attributes-Effective',
    '9a7ad942-ca53-11d1-bbd0-0080c76670c0': 'Allowed-Child-Classes',
    '9a7ad943-ca53-11d1-bbd0-0080c76670c0': 'Allowed-Child-Classes-Effective',
    '00fbf30c-91fe-11d1-aebc-0000f80367c1': 'Alt-Security-Identities',
    '45b01500-c419-11d1-bbc9-0080c76670c0': 'ANR',
    '96a7dd65-9118-11d1-aebc-0000f80367c1': 'App-Schema-Version',
    'dd712226-10e4-11d0-a05f-00aa006c33ed': 'Application-Name',
    '8297931d-86d3-11d0-afda-00c04fd930c9': 'Applies-To',
    'ba305f75-47e3-11d0-a1a6-00c04fd930c9': 'Asset-Number',
    '0296c11c-40da-11d1-a9c0-0000f80367c1': 'Assistant',
    '398f63c0-ca60-11d1-bbd1-0000f81f10c0': 'Assoc-NT-Account',
    '3320fc38-c379-4c17-a510-1bdf6133c5da': 'associatedDomain',
    'f7fbfc45-85ab-42a4-a435-780e62f7858b': 'associatedName',
    'cb843f80-48d9-11d1-a9c3-0000f80367c1': 'Attribute-Display-Names',
    'bf967922-0de6-11d0-a285-00aa003049e2': 'Attribute-ID',
    'bf967924-0de6-11d0-a285-00aa003049e2': 'Attribute-Security-GUID',
    'bf967925-0de6-11d0-a285-00aa003049e2': 'Attribute-Syntax',
    '9a7ad944-ca53-11d1-bbd0-0080c76670c0': 'Attribute-Types',
    'fa4693bb-7bc2-4cb9-81a8-c99c43b7905e': 'attributeCertificateAttribute',
    'd0e1d224-e1a0-42ce-a2da-793ba5244f35': 'audio',
    '6da8a4fe-0e52-11d0-a286-00aa003049e2': 'Auditing-Policy',
    'bf967928-0de6-11d0-a285-00aa003049e2': 'Authentication-Options',
    '1677578d-47f3-11d1-a9c3-0000f80367c1': 'Authority-Revocation-List',
    'bf96792c-0de6-11d0-a285-00aa003049e2': 'Auxiliary-Class',
    'bf96792d-0de6-11d0-a285-00aa003049e2': 'Bad-Password-Time',
    'bf96792e-0de6-11d0-a285-00aa003049e2': 'Bad-Pwd-Count',
    '1f0075f9-7e40-11d0-afd6-00c04fd930c9': 'Birth-Location',
    'e3f3cb4e-0f20-42eb-9703-d2ff26e52667': 'BootFile',
    'd72a0750-8c7c-416e-8714-e65f11e908be': 'BootParameter',
    'd50c2cdb-8951-11d1-aebc-0000f80367c1': 'Bridgehead-Server-List-BL',
    'd50c2cda-8951-11d1-aebc-0000f80367c1': 'Bridgehead-Transport-List',
    'f87fa54b-b2c5-4fd7-88c0-daccb21d93c5': 'buildingName',
    'bf96792f-0de6-11d0-a285-00aa003049e2': 'Builtin-Creation-Time',
    'bf967930-0de6-11d0-a285-00aa003049e2': 'Builtin-Modified-Count',
    'bf967931-0de6-11d0-a285-00aa003049e2': 'Business-Category',
    'ba305f76-47e3-11d0-a1a6-00c04fd930c9': 'Bytes-Per-Minute',
    'bf967932-0de6-11d0-a285-00aa003049e2': 'CA-Certificate',
    '963d2740-48be-11d1-a9c3-0000f80367c1': 'CA-Certificate-DN',
    '963d2735-48be-11d1-a9c3-0000f80367c1': 'CA-Connect',
    '963d2738-48be-11d1-a9c3-0000f80367c1': 'CA-Usages',
    '963d2736-48be-11d1-a9c3-0000f80367c1': 'CA-WEB-URL',
    'd9e18314-8939-11d1-aebc-0000f80367c1': 'Can-Upgrade-Script',
    '9a7ad945-ca53-11d1-bbd0-0080c76670c0': 'Canonical-Name',
    'd4159c92-957d-4a87-8a67-8d2934e01649': 'carLicense',
    '7bfdcb81-4807-11d1-a9c3-0000f80367c1': 'Catalogs',
    '7bfdcb7e-4807-11d1-a9c3-0000f80367c1': 'Categories',
    '7d6c0e94-7e20-11d0-afd6-00c04fd930c9': 'Category-Id',
    '963d2732-48be-11d1-a9c3-0000f80367c1': 'Certificate-Authority-Object',
    '1677579f-47f3-11d1-a9c3-0000f80367c1': 'Certificate-Revocation-List',
    '2a39c5b1-8960-11d1-aebc-0000f80367c1': 'Certificate-Templates',
    '548e1c22-dea6-11d0-b010-0000f80367c1': 'Class-Display-Name',
    'bf967938-0de6-11d0-a285-00aa003049e2': 'Code-Page',
    'bf96793b-0de6-11d0-a285-00aa003049e2': 'COM-ClassID',
    '281416d9-1968-11d0-a28f-00aa003049e2': 'COM-CLSID',
    'bf96793c-0de6-11d0-a285-00aa003049e2': 'COM-InterfaceID',
    '281416dd-1968-11d0-a28f-00aa003049e2': 'COM-Other-Prog-Id',
    'bf96793d-0de6-11d0-a285-00aa003049e2': 'COM-ProgID',
    '281416db-1968-11d0-a28f-00aa003049e2': 'COM-Treat-As-Class-Id',
    '281416de-1968-11d0-a28f-00aa003049e2': 'COM-Typelib-Id',
    '281416da-1968-11d0-a28f-00aa003049e2': 'COM-Unique-LIBID',
    'bf96793e-0de6-11d0-a285-00aa003049e2': 'Comment',
    'bf96793f-0de6-11d0-a285-00aa003049e2': 'Common-Name',
    'f0f8ff88-1191-11d0-a060-00aa006c33ed': 'Company',
    'bf967943-0de6-11d0-a285-00aa003049e2': 'Content-Indexing-Allowed',
    '4d8601ee-ac85-11d0-afe3-00c04fd930c9': 'Context-Menu',
    '6da8a4fc-0e52-11d0-a286-00aa003049e2': 'Control-Access-Rights',
    'bf967944-0de6-11d0-a285-00aa003049e2': 'Cost',
    '5fd42471-1262-11d0-a060-00aa006c33ed': 'Country-Code',
    'bf967945-0de6-11d0-a285-00aa003049e2': 'Country-Name',
    '2b09958a-8931-11d1-aebc-0000f80367c1': 'Create-Dialog',
    '2df90d73-009f-11d2-aa4c-00c04fd7d83a': 'Create-Time-Stamp',
    '2b09958b-8931-11d1-aebc-0000f80367c1': 'Create-Wizard-Ext',
    'bf967946-0de6-11d0-a285-00aa003049e2': 'Creation-Time',
    '4d8601ed-ac85-11d0-afe3-00c04fd930c9': 'Creation-Wizard',
    '7bfdcb85-4807-11d1-a9c3-0000f80367c1': 'Creator',
    '963d2737-48be-11d1-a9c3-0000f80367c1': 'CRL-Object',
    '963d2731-48be-11d1-a9c3-0000f80367c1': 'CRL-Partitioned-Revocation-List',
    '167757b2-47f3-11d1-a9c3-0000f80367c1': 'Cross-Certificate-Pair',
    '1f0075fe-7e40-11d0-afd6-00c04fd930c9': 'Curr-Machine-Id',
    '1f0075fc-7e40-11d0-afd6-00c04fd930c9': 'Current-Location',
    '963d273f-48be-11d1-a9c3-0000f80367c1': 'Current-Parent-CA',
    'bf967947-0de6-11d0-a285-00aa003049e2': 'Current-Value',
    'bf96799c-0de6-11d0-a285-00aa003049e2': 'DBCS-Pwd',
    'bf967948-0de6-11d0-a285-00aa003049e2': 'Default-Class-Store',
    '720bc4e2-a54a-11d0-afdf-00c04fd930c9': 'Default-Group',
    'b7b13116-b82e-11d0-afee-0000f80367c1': 'Default-Hiding-Value',
    'bf96799f-0de6-11d0-a285-00aa003049e2': 'Default-Local-Policy-Object',
    '26d97367-6070-11d1-a9c6-0000f80367c1': 'Default-Object-Category',
    '281416c8-1968-11d0-a28f-00aa003049e2': 'Default-Priority',
    '807a6d30-1669-11d0-a064-00aa006c33ed': 'Default-Security-Descriptor',
    '167757b5-47f3-11d1-a9c3-0000f80367c1': 'Delta-Revocation-List',
    'bf96794f-0de6-11d0-a285-00aa003049e2': 'Department',
    'be9ef6ee-cbc7-4f22-b27b-96967e7ee585': 'departmentNumber',
    'bf967950-0de6-11d0-a285-00aa003049e2': 'Description',
    'eea65906-8ac6-11d0-afda-00c04fd930c9': 'Desktop-Profile',
    'bf967951-0de6-11d0-a285-00aa003049e2': 'Destination-Indicator',
    '963d2750-48be-11d1-a9c3-0000f80367c1': 'dhcp-Classes',
    '963d2741-48be-11d1-a9c3-0000f80367c1': 'dhcp-Flags',
    '963d2742-48be-11d1-a9c3-0000f80367c1': 'dhcp-Identification',
    '963d2747-48be-11d1-a9c3-0000f80367c1': 'dhcp-Mask',
    '963d2754-48be-11d1-a9c3-0000f80367c1': 'dhcp-MaxKey',
    '963d2744-48be-11d1-a9c3-0000f80367c1': 'dhcp-Obj-Description',
    '963d2743-48be-11d1-a9c3-0000f80367c1': 'dhcp-Obj-Name',
    '963d274f-48be-11d1-a9c3-0000f80367c1': 'dhcp-Options',
    '963d2753-48be-11d1-a9c3-0000f80367c1': 'dhcp-Properties',
    '963d2748-48be-11d1-a9c3-0000f80367c1': 'dhcp-Ranges',
    '963d274a-48be-11d1-a9c3-0000f80367c1': 'dhcp-Reservations',
    '963d2745-48be-11d1-a9c3-0000f80367c1': 'dhcp-Servers',
    '963d2749-48be-11d1-a9c3-0000f80367c1': 'dhcp-Sites',
    '963d2752-48be-11d1-a9c3-0000f80367c1': 'dhcp-State',
    '963d2746-48be-11d1-a9c3-0000f80367c1': 'dhcp-Subnets',
    '963d273b-48be-11d1-a9c3-0000f80367c1': 'dhcp-Type',
    '963d273a-48be-11d1-a9c3-0000f80367c1': 'dhcp-Unique-Key',
    '963d2755-48be-11d1-a9c3-0000f80367c1': 'dhcp-Update-Time',
    'bf967953-0de6-11d0-a285-00aa003049e2': 'Display-Name',
    'bf967954-0de6-11d0-a285-00aa003049e2': 'Display-Name-Printable',
    '9a7ad946-ca53-11d1-bbd0-0080c76670c0': 'DIT-Content-Rules',
    'fe6136a0-2073-11d0-a9c2-00aa006c33ed': 'Division',
    'f0f8ff8b-1191-11d0-a060-00aa006c33ed': 'DMD-Location',
    '167757b9-47f3-11d1-a9c3-0000f80367c1': 'DMD-Name',
    '2df90d86-009f-11d2-aa4c-00c04fd7d83a': 'DN-Reference-Update',
    'e0fa1e65-9b45-11d0-afdd-00c04fd930c9': 'Dns-Allow-Dynamic',
    'e0fa1e66-9b45-11d0-afdd-00c04fd930c9': 'Dns-Allow-XFR',
    '72e39547-7b18-11d1-adef-00c04fd8d5cd': 'DNS-Host-Name',
    'e0fa1e68-9b45-11d0-afdd-00c04fd930c9': 'Dns-Notify-Secondaries',
    '675a15fe-3b70-11d2-90cc-00c04fd91ab1': 'DNS-Property',
    'e0fa1e69-9b45-11d0-afdd-00c04fd930c9': 'Dns-Record',
    'bf967959-0de6-11d0-a285-00aa003049e2': 'Dns-Root',
    'e0fa1e67-9b45-11d0-afdd-00c04fd930c9': 'Dns-Secure-Secondaries',
    'd5eb2eb7-be4e-463b-a214-634a44d7392e': 'DNS-Tombstoned',
    'f18a8e19-af5f-4478-b096-6f35c27eb83f': 'documentAuthor',
    '0b21ce82-ff63-46d9-90fb-c8b9f24e97b9': 'documentIdentifier',
    'b958b14e-ac6d-4ec4-8892-be70b69f7281': 'documentLocation',
    '170f09d7-eb69-448a-9a30-f1afecfd32d7': 'documentPublisher',
    'de265a9c-ff2c-47b9-91dc-6e6fe2c43062': 'documentTitle',
    '94b3a8a9-d613-4cec-9aad-5fbcc1046b43': 'documentVersion',
    '7bfdcb7a-4807-11d1-a9c3-0000f80367c1': 'Domain-Certificate-Authorities',
    '19195a55-6da0-11d0-afd3-00c04fd930c9': 'Domain-Component',
    'b000ea7b-a086-11d0-afdd-00c04fd930c9': 'Domain-Cross-Ref',
    '963d2734-48be-11d1-a9c3-0000f80367c1': 'Domain-ID',
    '7f561278-5301-11d1-a9c5-0000f80367c1': 'Domain-Identifier',
    'bf96795d-0de6-11d0-a285-00aa003049e2': 'Domain-Policy-Object',
    '80a67e2a-9f22-11d0-afdd-00c04fd930c9': 'Domain-Policy-Reference',
    'bf96795e-0de6-11d0-a285-00aa003049e2': 'Domain-Replica',
    '80a67e29-9f22-11d0-afdd-00c04fd930c9': 'Domain-Wide-Policy',
    '1a1aa5b5-262e-4df6-af04-2cf6b0d80048': 'drink',
    '281416c5-1968-11d0-a28f-00aa003049e2': 'Driver-Name',
    'ba305f6e-47e3-11d0-a1a6-00c04fd930c9': 'Driver-Version',
    'd167aa4b-8b08-11d2-9939-0000f87a57d4': 'DS-Core-Propagation-Data',
    'f0f8ff86-1191-11d0-a060-00aa006c33ed': 'DS-Heuristics',
    'ee8d0ae0-6f91-11d2-9905-0000f87a57d4': 'DS-UI-Admin-Maximum',
    'f6ea0a94-6f91-11d2-9905-0000f87a57d4': 'DS-UI-Admin-Notification',
    'fcca766a-6f91-11d2-9905-0000f87a57d4': 'DS-UI-Shell-Maximum',
    '167757bc-47f3-11d1-a9c3-0000f80367c1': 'DSA-Signature',
    '52458021-ca6a-11d0-afff-0000f80367c1': 'Dynamic-LDAP-Server',
    'bf967961-0de6-11d0-a285-00aa003049e2': 'E-mail-Addresses',
    '8e4eb2ec-4712-11d0-a1a0-00c04fd930c9': 'EFSPolicy',
    'bf967962-0de6-11d0-a285-00aa003049e2': 'Employee-ID',
    'a8df73ef-c5ea-11d1-bbcb-0080c76670c0': 'Employee-Number',
    'a8df73f0-c5ea-11d1-bbcb-0080c76670c0': 'Employee-Type',
    'a8df73f2-c5ea-11d1-bbcb-0080c76670c0': 'Enabled',
    'bf967963-0de6-11d0-a285-00aa003049e2': 'Enabled-Connection',
    '2a39c5b3-8960-11d1-aebc-0000f80367c1': 'Enrollment-Providers',
    'd213decc-d81a-4384-aac2-dcfcfd631cf8': 'Entry-TTL',
    '9a7ad947-ca53-11d1-bbd0-0080c76670c0': 'Extended-Attribute-Info',
    'bf967966-0de6-11d0-a285-00aa003049e2': 'Extended-Chars-Allowed',
    '9a7ad948-ca53-11d1-bbd0-0080c76670c0': 'Extended-Class-Info',
    'bf967972-0de6-11d0-a285-00aa003049e2': 'Extension-Name',
    'd24e2846-1dd9-4bcf-99d7-a6227cc86da7': 'Extra-Columns',
    'bf967974-0de6-11d0-a285-00aa003049e2': 'Facsimile-Telephone-Number',
    'd9e18315-8939-11d1-aebc-0000f80367c1': 'File-Ext-Priority',
    'bf967976-0de6-11d0-a285-00aa003049e2': 'Flags',
    'b7b13117-b82e-11d0-afee-0000f80367c1': 'Flat-Name',
    'bf967977-0de6-11d0-a285-00aa003049e2': 'Force-Logoff',
    '3e97891e-8c01-11d0-afda-00c04fd930c9': 'Foreign-Identifier',
    '7bfdcb88-4807-11d1-a9c3-0000f80367c1': 'Friendly-Names',
    '9a7ad949-ca53-11d1-bbd0-0080c76670c0': 'From-Entry',
    'bf967979-0de6-11d0-a285-00aa003049e2': 'From-Server',
    '2a132578-9373-11d1-aebc-0000f80367c1': 'Frs-Computer-Reference',
    '2a132579-9373-11d1-aebc-0000f80367c1': 'Frs-Computer-Reference-BL',
    '2a13257a-9373-11d1-aebc-0000f80367c1': 'FRS-Control-Data-Creation',
    '2a13257b-9373-11d1-aebc-0000f80367c1': 'FRS-Control-Inbound-Backlog',
    '2a13257c-9373-11d1-aebc-0000f80367c1': 'FRS-Control-Outbound-Backlog',
    '1be8f171-a9ff-11d0-afe2-00c04fd930c9': 'FRS-Directory-Filter',
    '1be8f177-a9ff-11d0-afe2-00c04fd930c9': 'FRS-DS-Poll',
    '52458020-ca6a-11d0-afff-0000f80367c1': 'FRS-Extensions',
    '1be8f178-a9ff-11d0-afe2-00c04fd930c9': 'FRS-Fault-Condition',
    '1be8f170-a9ff-11d0-afe2-00c04fd930c9': 'FRS-File-Filter',
    '2a13257d-9373-11d1-aebc-0000f80367c1': 'FRS-Flags',
    '5245801e-ca6a-11d0-afff-0000f80367c1': 'FRS-Level-Limit',
    '2a13257e-9373-11d1-aebc-0000f80367c1': 'FRS-Member-Reference',
    '2a13257f-9373-11d1-aebc-0000f80367c1': 'FRS-Member-Reference-BL',
    '2a132580-9373-11d1-aebc-0000f80367c1': 'FRS-Partner-Auth-Level',
    '2a132581-9373-11d1-aebc-0000f80367c1': 'FRS-Primary-Member',
    '5245801a-ca6a-11d0-afff-0000f80367c1': 'FRS-Replica-Set-GUID',
    '26d9736b-6070-11d1-a9c6-0000f80367c1': 'FRS-Replica-Set-Type',
    '1be8f174-a9ff-11d0-afe2-00c04fd930c9': 'FRS-Root-Path',
    '5245801f-ca6a-11d0-afff-0000f80367c1': 'FRS-Root-Security',
    'ddac0cee-af8f-11d0-afeb-00c04fd930c9': 'FRS-Service-Command',
    '2a132582-9373-11d1-aebc-0000f80367c1': 'FRS-Service-Command-Status',
    '1be8f175-a9ff-11d0-afe2-00c04fd930c9': 'FRS-Staging-Path',
    '2a132583-9373-11d1-aebc-0000f80367c1': 'FRS-Time-Last-Command',
    '2a132584-9373-11d1-aebc-0000f80367c1': 'FRS-Time-Last-Config-Change',
    '1be8f172-a9ff-11d0-afe2-00c04fd930c9': 'FRS-Update-Timeout',
    '2a132585-9373-11d1-aebc-0000f80367c1': 'FRS-Version',
    '26d9736c-6070-11d1-a9c6-0000f80367c1': 'FRS-Version-GUID',
    '1be8f173-a9ff-11d0-afe2-00c04fd930c9': 'FRS-Working-Path',
    '66171887-8f3c-11d0-afda-00c04fd930c9': 'FSMO-Role-Owner',
    '5fd424a1-1262-11d0-a060-00aa006c33ed': 'Garbage-Coll-Period',
    'a3e03f1f-1d55-4253-a0af-30c2a784e46e': 'Gecos',
    'bf96797a-0de6-11d0-a285-00aa003049e2': 'Generated-Connection',
    '16775804-47f3-11d1-a9c3-0000f80367c1': 'Generation-Qualifier',
    'c5b95f0c-ec9e-41c4-849c-b46597ed6696': 'GidNumber',
    'f0f8ff8e-1191-11d0-a060-00aa006c33ed': 'Given-Name',
    'f754c748-06f4-11d2-aa53-00c04fd7d83a': 'Global-Address-List',
    '4898f63d-4112-477c-8826-3ca00bd8277d': 'Global-Address-List2',
    'bf96797d-0de6-11d0-a285-00aa003049e2': 'Governs-ID',
    'f30e3bbe-9ff0-11d1-b603-0000f80367c1': 'GP-Link',
    'f30e3bbf-9ff0-11d1-b603-0000f80367c1': 'GP-Options',
    'f30e3bc1-9ff0-11d1-b603-0000f80367c1': 'GPC-File-Sys-Path',
    'f30e3bc0-9ff0-11d1-b603-0000f80367c1': 'GPC-Functionality-Version',
    '32ff8ecc-783f-11d2-9916-0000f87a57d4': 'GPC-Machine-Extension-Names',
    '42a75fc6-783f-11d2-9916-0000f87a57d4': 'GPC-User-Extension-Names',
    '7bd4c7a6-1add-4436-8c04-3999a880154c': 'GPC-WQL-Filter',
    'bf96797e-0de6-11d0-a285-00aa003049e2': 'Group-Attributes',
    'bf967980-0de6-11d0-a285-00aa003049e2': 'Group-Membership-SAM',
    'eea65905-8ac6-11d0-afda-00c04fd930c9': 'Group-Priority',
    '9a9a021e-4a5b-11d1-a9c3-0000f80367c1': 'Group-Type',
    'eea65904-8ac6-11d0-afda-00c04fd930c9': 'Groups-to-Ignore',
    'bf967982-0de6-11d0-a285-00aa003049e2': 'Has-Master-NCs',
    'bf967981-0de6-11d0-a285-00aa003049e2': 'Has-Partial-Replica-NCs',
    '5fd424a7-1262-11d0-a060-00aa006c33ed': 'Help-Data16',
    '5fd424a8-1262-11d0-a060-00aa006c33ed': 'Help-Data32',
    '5fd424a9-1262-11d0-a060-00aa006c33ed': 'Help-File-Name',
    'ec05b750-a977-4efe-8e8d-ba6c1a6e33a8': 'Hide-From-AB',
    'bf967985-0de6-11d0-a285-00aa003049e2': 'Home-Directory',
    'bf967986-0de6-11d0-a285-00aa003049e2': 'Home-Drive',
    '6043df71-fa48-46cf-ab7c-cbd54644b22d': 'host',
    'a45398b7-c44a-4eb6-82d3-13c10946dbfe': 'houseIdentifier',
    'f0f8ff83-1191-11d0-a060-00aa006c33ed': 'Icon-Path',
    '7d6c0e92-7e20-11d0-afd6-00c04fd930c9': 'Implemented-Categories',
    '7bfdcb87-4807-11d1-a9c3-0000f80367c1': 'IndexedScopes',
    '52458023-ca6a-11d0-afff-0000f80367c1': 'Initial-Auth-Incoming',
    '52458024-ca6a-11d0-afff-0000f80367c1': 'Initial-Auth-Outgoing',
    'f0f8ff90-1191-11d0-a060-00aa006c33ed': 'Initials',
    '96a7dd64-9118-11d1-aebc-0000f80367c1': 'Install-Ui-Level',
    'bf96798c-0de6-11d0-a285-00aa003049e2': 'Instance-Type',
    'b7c69e60-2cc7-11d2-854e-00a0c983f608': 'Inter-Site-Topology-Failover',
    'b7c69e5e-2cc7-11d2-854e-00a0c983f608': 'Inter-Site-Topology-Generator',
    'b7c69e5f-2cc7-11d2-854e-00a0c983f608': 'Inter-Site-Topology-Renew',
    'bf96798d-0de6-11d0-a285-00aa003049e2': 'International-ISDN-Number',
    'bf96798e-0de6-11d0-a285-00aa003049e2': 'Invocation-Id',
    'de8bb721-85dc-4fde-b687-9657688e667e': 'IpHostNumber',
    '6ff64fcd-462e-4f62-b44a-9a5347659eb9': 'IpNetmaskNumber',
    '4e3854f4-3087-42a4-a813-bb0c528958d3': 'IpNetworkNumber',
    'ebf5c6eb-0e2d-4415-9670-1081993b4211': 'IpProtocolNumber',
    'b40ff81f-427a-11d1-a9c2-0000f80367c1': 'Ipsec-Data',
    'b40ff81e-427a-11d1-a9c2-0000f80367c1': 'Ipsec-Data-Type',
    'b40ff823-427a-11d1-a9c2-0000f80367c1': 'Ipsec-Filter-Reference',
    'b40ff81d-427a-11d1-a9c2-0000f80367c1': 'Ipsec-ID',
    'b40ff820-427a-11d1-a9c2-0000f80367c1': 'Ipsec-ISAKMP-Reference',
    'b40ff81c-427a-11d1-a9c2-0000f80367c1': 'Ipsec-Name',
    '07383075-91df-11d1-aebc-0000f80367c1': 'IPSEC-Negotiation-Policy-Action',
    'b40ff822-427a-11d1-a9c2-0000f80367c1': 'Ipsec-Negotiation-Policy-Reference',
    '07383074-91df-11d1-aebc-0000f80367c1': 'IPSEC-Negotiation-Policy-Type',
    'b40ff821-427a-11d1-a9c2-0000f80367c1': 'Ipsec-NFA-Reference',
    'b40ff824-427a-11d1-a9c2-0000f80367c1': 'Ipsec-Owners-Reference',
    'b7b13118-b82e-11d0-afee-0000f80367c1': 'Ipsec-Policy-Reference',
    'ff2daebf-f463-495a-8405-3e483641eaa2': 'IpServicePort',
    'cd96ec0b-1ed6-43b4-b26b-f170b645883f': 'IpServiceProtocol',
    '00fbf30d-91fe-11d1-aebc-0000f80367c1': 'Is-Critical-System-Object',
    '28630ebe-41d5-11d1-a9c1-0000f80367c1': 'Is-Defunct',
    'bf96798f-0de6-11d0-a285-00aa003049e2': 'Is-Deleted',
    'f4c453f0-c5f1-11d1-bbcb-0080c76670c0': 'Is-Ephemeral',
    'bf967991-0de6-11d0-a285-00aa003049e2': 'Is-Member-Of-DL',
    '19405b9d-3cfa-11d1-a9c0-0000f80367c1': 'Is-Member-Of-Partial-Attribute-Set',
    '19405b9c-3cfa-11d1-a9c0-0000f80367c1': 'Is-Privilege-Holder',
    '8fb59256-55f1-444b-aacb-f5b482fe3459': 'Is-Recycled',
    'bf967992-0de6-11d0-a285-00aa003049e2': 'Is-Single-Valued',
    'bac80572-09c4-4fa9-9ae6-7628d7adbe0e': 'jpegPhoto',
    'bf967993-0de6-11d0-a285-00aa003049e2': 'Keywords',
    '1677581f-47f3-11d1-a9c3-0000f80367c1': 'Knowledge-Information',
    'c569bb46-c680-44bc-a273-e6c227d71b45': 'labeledURI',
    '1fbb0be8-ba63-11d0-afef-0000f80367c1': 'Last-Backup-Restoration-Time',
    'bf967995-0de6-11d0-a285-00aa003049e2': 'Last-Content-Indexed',
    '52ab8670-5709-11d1-a9c6-0000f80367c1': 'Last-Known-Parent',
    'bf967996-0de6-11d0-a285-00aa003049e2': 'Last-Logoff',
    'bf967997-0de6-11d0-a285-00aa003049e2': 'Last-Logon',
    'c0e20a04-0e5a-4ff3-9482-5efeaecd7060': 'Last-Logon-Timestamp',
    'bf967998-0de6-11d0-a285-00aa003049e2': 'Last-Set-Time',
    '7d6c0e9c-7e20-11d0-afd6-00c04fd930c9': 'Last-Update-Sequence',
    '7359a352-90f7-11d1-aebc-0000f80367c1': 'LDAP-Admin-Limits',
    'bf96799a-0de6-11d0-a285-00aa003049e2': 'LDAP-Display-Name',
    '7359a353-90f7-11d1-aebc-0000f80367c1': 'LDAP-IPDeny-List',
    '28630ebc-41d5-11d1-a9c1-0000f80367c1': 'Legacy-Exchange-DN',
    'bf96799b-0de6-11d0-a285-00aa003049e2': 'Link-ID',
    '2ae80fe2-47b4-11d0-a1a4-00c04fd930c9': 'Link-Track-Secret',
    'bf96799d-0de6-11d0-a285-00aa003049e2': 'Lm-Pwd-History',
    'bf96799e-0de6-11d0-a285-00aa003049e2': 'Local-Policy-Flags',
    '80a67e4d-9f22-11d0-afdd-00c04fd930c9': 'Local-Policy-Reference',
    'bf9679a1-0de6-11d0-a285-00aa003049e2': 'Locale-ID',
    'bf9679a2-0de6-11d0-a285-00aa003049e2': 'Locality-Name',
    'a746f0d1-78d0-11d2-9916-0000f87a57d4': 'Localization-Display-Id',
    'd9e18316-8939-11d1-aebc-0000f80367c1': 'Localized-Description',
    '09dcb79f-165f-11d0-a064-00aa006c33ed': 'Location',
    'bf9679a4-0de6-11d0-a285-00aa003049e2': 'Lock-Out-Observation-Window',
    'bf9679a5-0de6-11d0-a285-00aa003049e2': 'Lockout-Duration',
    'bf9679a6-0de6-11d0-a285-00aa003049e2': 'Lockout-Threshold',
    '28630ebf-41d5-11d1-a9c1-0000f80367c1': 'Lockout-Time',
    'a553d12c-3231-4c5e-8adf-8d189697721e': 'LoginShell',
    'bf9679a9-0de6-11d0-a285-00aa003049e2': 'Logo',
    'bf9679aa-0de6-11d0-a285-00aa003049e2': 'Logon-Count',
    'bf9679ab-0de6-11d0-a285-00aa003049e2': 'Logon-Hours',
    'bf9679ac-0de6-11d0-a285-00aa003049e2': 'Logon-Workstation',
    'bf9679ad-0de6-11d0-a285-00aa003049e2': 'LSA-Creation-Time',
    'bf9679ae-0de6-11d0-a285-00aa003049e2': 'LSA-Modified-Count',
    'e6a522dd-9770-43e1-89de-1de5044328f7': 'MacAddress',
    'bf9679af-0de6-11d0-a285-00aa003049e2': 'Machine-Architecture',
    'c9b6358e-bb38-11d0-afef-0000f80367c1': 'Machine-Password-Change-Interval',
    'bf9679b2-0de6-11d0-a285-00aa003049e2': 'Machine-Role',
    '80a67e4f-9f22-11d0-afdd-00c04fd930c9': 'Machine-Wide-Policy',
    '0296c120-40da-11d1-a9c0-0000f80367c1': 'Managed-By',
    '0296c124-40da-11d1-a9c0-0000f80367c1': 'Managed-Objects',
    'bf9679b5-0de6-11d0-a285-00aa003049e2': 'Manager',
    'bf9679b7-0de6-11d0-a285-00aa003049e2': 'MAPI-ID',
    'bf9679b9-0de6-11d0-a285-00aa003049e2': 'Marshalled-Interface',
    'e48e64e0-12c9-11d3-9102-00c04fd91ab1': 'Mastered-By',
    'bf9679bb-0de6-11d0-a285-00aa003049e2': 'Max-Pwd-Age',
    'bf9679bc-0de6-11d0-a285-00aa003049e2': 'Max-Renew-Age',
    'bf9679bd-0de6-11d0-a285-00aa003049e2': 'Max-Storage',
    'bf9679be-0de6-11d0-a285-00aa003049e2': 'Max-Ticket-Age',
    'bf9679bf-0de6-11d0-a285-00aa003049e2': 'May-Contain',
    '11b6cc8b-48c4-11d1-a9c3-0000f80367c1': 'meetingAdvertiseScope',
    '11b6cc83-48c4-11d1-a9c3-0000f80367c1': 'meetingApplication',
    '11b6cc92-48c4-11d1-a9c3-0000f80367c1': 'meetingBandwidth',
    '11b6cc93-48c4-11d1-a9c3-0000f80367c1': 'meetingBlob',
    '11b6cc87-48c4-11d1-a9c3-0000f80367c1': 'meetingContactInfo',
    '11b6cc7e-48c4-11d1-a9c3-0000f80367c1': 'meetingDescription',
    '11b6cc91-48c4-11d1-a9c3-0000f80367c1': 'meetingEndTime',
    '11b6cc7c-48c4-11d1-a9c3-0000f80367c1': 'meetingID',
    '11b6cc89-48c4-11d1-a9c3-0000f80367c1': 'meetingIP',
    '11b6cc8e-48c4-11d1-a9c3-0000f80367c1': 'meetingIsEncrypted',
    '11b6cc7f-48c4-11d1-a9c3-0000f80367c1': 'meetingKeyword',
    '11b6cc84-48c4-11d1-a9c3-0000f80367c1': 'meetingLanguage',
    '11b6cc80-48c4-11d1-a9c3-0000f80367c1': 'meetingLocation',
    '11b6cc85-48c4-11d1-a9c3-0000f80367c1': 'meetingMaxParticipants',
    '11b6cc7d-48c4-11d1-a9c3-0000f80367c1': 'meetingName',
    '11b6cc86-48c4-11d1-a9c3-0000f80367c1': 'meetingOriginator',
    '11b6cc88-48c4-11d1-a9c3-0000f80367c1': 'meetingOwner',
    '11b6cc81-48c4-11d1-a9c3-0000f80367c1': 'meetingProtocol',
    '11b6cc8d-48c4-11d1-a9c3-0000f80367c1': 'meetingRating',
    '11b6cc8f-48c4-11d1-a9c3-0000f80367c1': 'meetingRecurrence',
    '11b6cc8a-48c4-11d1-a9c3-0000f80367c1': 'meetingScope',
    '11b6cc90-48c4-11d1-a9c3-0000f80367c1': 'meetingStartTime',
    '11b6cc82-48c4-11d1-a9c3-0000f80367c1': 'meetingType',
    '11b6cc8c-48c4-11d1-a9c3-0000f80367c1': 'meetingURL',
    'bf9679c0-0de6-11d0-a285-00aa003049e2': 'Member',
    '0f6a17dc-53e5-4be8-9442-8f3ce2f9012a': 'MemberNisNetgroup',
    '03dab236-672e-4f61-ab64-f77d2dc2ffab': 'MemberUid',
    '0296c122-40da-11d1-a9c0-0000f80367c1': 'MHS-OR-Address',
    'bf9679c2-0de6-11d0-a285-00aa003049e2': 'Min-Pwd-Age',
    'bf9679c3-0de6-11d0-a285-00aa003049e2': 'Min-Pwd-Length',
    'bf9679c4-0de6-11d0-a285-00aa003049e2': 'Min-Ticket-Age',
    'bf9679c5-0de6-11d0-a285-00aa003049e2': 'Modified-Count',
    'bf9679c6-0de6-11d0-a285-00aa003049e2': 'Modified-Count-At-Last-Prom',
    '9a7ad94a-ca53-11d1-bbd0-0080c76670c0': 'Modify-Time-Stamp',
    'bf9679c7-0de6-11d0-a285-00aa003049e2': 'Moniker',
    'bf9679c8-0de6-11d0-a285-00aa003049e2': 'Moniker-Display-Name',
    '1f2ac2c8-3b71-11d2-90cc-00c04fd91ab1': 'Move-Tree-State',
    '62f29b60-be74-4630-9456-2f6691993a86': 'ms-Authz-Central-Access-Policy-ID',
    '07831919-8f94-4fb6-8a42-91545dccdad3': 'ms-Authz-Effective-Security-Policy',
    '8e1685c6-3e2f-48a2-a58d-5af0ea789fa0': 'ms-Authz-Last-Effective-Security-Policy',
    '57f22f7a-377e-42c3-9872-cec6f21d2e3e': 'ms-Authz-Member-Rules-In-Central-Access-Policy',
    '516e67cf-fedd-4494-bb3a-bc506a948891': 'ms-Authz-Member-Rules-In-Central-Access-Policy-BL',
    'b946bece-09b5-4b6a-b25a-4b63a330e80e': 'ms-Authz-Proposed-Security-Policy',
    '80997877-f874-4c68-864d-6e508a83bdbd': 'ms-Authz-Resource-Condition',
    '998b10f7-aa1a-4364-b867-753d197fe670': 'ms-COM-DefaultPartitionLink',
    '430f678b-889f-41f2-9843-203b5a65572f': 'ms-COM-ObjectId',
    '09abac62-043f-4702-ac2b-6ca15eee5754': 'ms-COM-PartitionLink',
    '67f121dc-7d02-4c7d-82f5-9ad4c950ac34': 'ms-COM-PartitionSetLink',
    '9e6f3a4d-242c-4f37-b068-36b57f9fc852': 'ms-COM-UserLink',
    '8e940c8a-e477-4367-b08d-ff2ff942dcd7': 'ms-COM-UserPartitionSetLink',
    'b786cec9-61fd-4523-b2c1-5ceb3860bb32': 'ms-DFS-Comment-v2',
    '35b8b3d9-c58f-43d6-930e-5040f2f1a781': 'ms-DFS-Generation-GUID-v2',
    '3c095e8a-314e-465b-83f5-ab8277bcf29b': 'ms-DFS-Last-Modified-v2',
    'edb027f3-5726-4dee-8d4e-dbf07e1ad1f1': 'ms-DFS-Link-Identity-GUID-v2',
    '86b021f6-10ab-40a2-a252-1dc0cc3be6a9': 'ms-DFS-Link-Path-v2',
    '57cf87f7-3426-4841-b322-02b3b6e9eba8': 'ms-DFS-Link-Security-Descriptor-v2',
    '200432ce-ec5f-4931-a525-d7f4afe34e68': 'ms-DFS-Namespace-Identity-GUID-v2',
    '0c3e5bc5-eb0e-40f5-9b53-334e958dffdb': 'ms-DFS-Properties-v2',
    'ec6d7855-704a-4f61-9aa6-c49a7c1d54c7': 'ms-DFS-Schema-Major-Version',
    'fef9a725-e8f1-43ab-bd86-6a0115ce9e38': 'ms-DFS-Schema-Minor-Version',
    '2d7826f0-4cf7-42e9-a039-1110e0d9ca99': 'ms-DFS-Short-Name-Link-Path-v2',
    '6ab126c6-fa41-4b36-809e-7ca91610d48f': 'ms-DFS-Target-List-v2',
    'ea944d31-864a-4349-ada5-062e2c614f5e': 'ms-DFS-Ttl-v2',
    'db7a08e7-fc76-4569-a45f-f5ecb66a88b5': 'ms-DFSR-CachePolicy',
    '936eac41-d257-4bb9-bd55-f310a3cf09ad': 'ms-DFSR-CommonStagingPath',
    '135eb00e-4846-458b-8ea2-a37559afd405': 'ms-DFSR-CommonStagingSizeInMb',
    '6c7b5785-3d21-41bf-8a8a-627941544d5a': 'ms-DFSR-ComputerReference',
    '5eb526d7-d71b-44ae-8cc6-95460052e6ac': 'ms-DFSR-ComputerReferenceBL',
    '5cf0bcc8-60f7-4bff-bda6-aea0344eb151': 'ms-DFSR-ConflictPath',
    '9ad33fc9-aacf-4299-bb3e-d1fc6ea88e49': 'ms-DFSR-ConflictSizeInMb',
    '1035a8e1-67a8-4c21-b7bb-031cdf99d7a0': 'ms-DFSR-ContentSetGuid',
    '87811bd5-cd8b-45cb-9f5d-980f3a9e0c97': 'ms-DFSR-DefaultCompressionExclusionFilter',
    '817cf0b8-db95-4914-b833-5a079ef65764': 'ms-DFSR-DeletedPath',
    '53ed9ad1-9975-41f4-83f5-0c061a12553a': 'ms-DFSR-DeletedSizeInMb',
    'f7b85ba9-3bf9-428f-aab4-2eee6d56f063': 'ms-DFSR-DfsLinkTarget',
    '2cc903e2-398c-443b-ac86-ff6b01eac7ba': 'ms-DFSR-DfsPath',
    '93c7b477-1f2e-4b40-b7bf-007e8d038ccf': 'ms-DFSR-DirectoryFilter',
    '6a84ede5-741e-43fd-9dd6-aa0f61578621': 'ms-DFSR-DisablePacketPrivacy',
    '03726ae7-8e7d-4446-8aae-a91657c00993': 'ms-DFSR-Enabled',
    '78f011ec-a766-4b19-adcf-7b81ed781a4d': 'ms-DFSR-Extension',
    'd68270ac-a5dc-4841-a6ac-cd68be38c181': 'ms-DFSR-FileFilter',
    'fe515695-3f61-45c8-9bfa-19c148c57b09': 'ms-DFSR-Flags',
    '048b4692-6227-4b67-a074-c4437083e14b': 'ms-DFSR-Keywords',
    '2ab0e48d-ac4e-4afc-83e5-a34240db6198': 'ms-DFSR-MaxAgeInCacheInMin',
    '261337aa-f1c3-44b2-bbea-c88d49e6f0c7': 'ms-DFSR-MemberReference',
    'adde62c6-1880-41ed-bd3c-30b7d25e14f0': 'ms-DFSR-MemberReferenceBL',
    '4c5d607a-ce49-444a-9862-82a95f5d1fcc': 'ms-DFSR-MinDurationCacheInMin',
    '7d523aff-9012-49b2-9925-f922a0018656': 'ms-DFSR-OnDemandExclusionDirectoryFilter',
    'a68359dc-a581-4ee6-9015-5382c60f0fb4': 'ms-DFSR-OnDemandExclusionFileFilter',
    'd6d67084-c720-417d-8647-b696237a114c': 'ms-DFSR-Options',
    '11e24318-4ca6-4f49-9afe-e5eb1afa3473': 'ms-DFSR-Options2',
    'eb20e7d6-32ad-42de-b141-16ad2631b01b': 'ms-DFSR-Priority',
    'e3b44e05-f4a7-4078-a730-f48670a743f8': 'ms-DFSR-RdcEnabled',
    'f402a330-ace5-4dc1-8cc9-74d900bf8ae0': 'ms-DFSR-RdcMinFileSizeInKb',
    '5ac48021-e447-46e7-9d23-92c0c6a90dfb': 'ms-DFSR-ReadOnly',
    '2dad8796-7619-4ff8-966e-0a5cc67b287f': 'ms-DFSR-ReplicationGroupGuid',
    'eeed0fc8-1001-45ed-80cc-bbf744930720': 'ms-DFSR-ReplicationGroupType',
    '51928e94-2cd8-4abe-b552-e50412444370': 'ms-DFSR-RootFence',
    'd7d5e8c1-e61f-464f-9fcf-20bbe0a2ec54': 'ms-DFSR-RootPath',
    '90b769ac-4413-43cf-ad7a-867142e740a3': 'ms-DFSR-RootSizeInMb',
    '4699f15f-a71f-48e2-9ff5-5897c0759205': 'ms-DFSR-Schedule',
    'd64b9c23-e1fa-467b-b317-6964d744d633': 'ms-DFSR-StagingCleanupTriggerInPercent',
    '86b9a69e-f0a6-405d-99bb-77d977992c2a': 'ms-DFSR-StagingPath',
    '250a8f20-f6fc-4559-ae65-e4b24c67aebe': 'ms-DFSR-StagingSizeInMb',
    '23e35d4c-e324-4861-a22f-e199140dae00': 'ms-DFSR-TombstoneExpiryInMin',
    '1a861408-38c3-49ea-ba75-85481a77c655': 'ms-DFSR-Version',
    '8f4e317f-28d7-442c-a6df-1f491f97b326': 'ms-DNS-DNSKEY-Record-Set-TTL',
    '28c458f5-602d-4ac9-a77c-b3f1be503a7e': 'ms-DNS-DNSKEY-Records',
    '5c5b7ad2-20fa-44bb-beb3-34b9c0f65579': 'ms-DNS-DS-Record-Algorithms',
    '29869b7c-64c4-42fe-97d5-fbc2fa124160': 'ms-DNS-DS-Record-Set-TTL',
    'aa12854c-d8fc-4d5e-91ca-368b8d829bee': 'ms-DNS-Is-Signed',
    '0be0dd3b-041a-418c-ace9-2f17d23e9d42': 'ms-DNS-Keymaster-Zones',
    '0dc063c1-52d9-4456-9e15-9c2434aafd94': 'ms-DNS-Maintain-Trust-Anchor',
    '387d9432-a6d1-4474-82cd-0a89aae084ae': 'ms-DNS-NSEC3-Current-Salt',
    'ff9e5552-7db7-4138-8888-05ce320a0323': 'ms-DNS-NSEC3-Hash-Algorithm',
    '80b70aab-8959-4ec0-8e93-126e76df3aca': 'ms-DNS-NSEC3-Iterations',
    '7bea2088-8ce2-423c-b191-66ec506b1595': 'ms-DNS-NSEC3-OptOut',
    '13361665-916c-4de7-a59d-b1ebbd0de129': 'ms-DNS-NSEC3-Random-Salt-Length',
    'aff16770-9622-4fbc-a128-3088777605b9': 'ms-DNS-NSEC3-User-Salt',
    '285c6964-c11a-499e-96d8-bf7c75a223c6': 'ms-DNS-Parent-Has-Secure-Delegation',
    'ba340d47-2181-4ca0-a2f6-fae4479dab2a': 'ms-DNS-Propagation-Time',
    '27d93c40-065a-43c0-bdd8-cdf2c7d120aa': 'ms-DNS-RFC5011-Key-Rollovers',
    'f6b0f0be-a8e4-4468-8fd9-c3c47b8722f9': 'ms-DNS-Secure-Delegation-Polling-Period',
    'c79f2199-6da1-46ff-923c-1f3f800c721e': 'ms-DNS-Sign-With-NSEC3',
    '03d4c32e-e217-4a61-9699-7bbc4729a026': 'ms-DNS-Signature-Inception-Offset',
    '3443d8cd-e5b6-4f3b-b098-659a0214a079': 'ms-DNS-Signing-Key-Descriptors',
    'b7673e6d-cad9-4e9e-b31a-63e8098fdd63': 'ms-DNS-Signing-Keys',
    'e85e1204-3434-41ad-9b56-e2901228fff0': 'MS-DRM-Identity-Certificate',
    '80863791-dbe9-4eb8-837e-7f0ab55d9ac7': 'ms-DS-Additional-Dns-Host-Name',
    '975571df-a4d5-429a-9f59-cdc6581d91e6': 'ms-DS-Additional-Sam-Account-Name',
    'd3aa4a5c-4e03-4810-97aa-2b339e7a434b': 'MS-DS-All-Users-Trust-Quota',
    '8469441b-9ac4-4e45-8205-bd219dbf672d': 'ms-DS-Allowed-DNS-Suffixes',
    '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79': 'ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity',
    '800d94d7-b7a1-42a1-b14d-7cae1423d07f': 'ms-DS-Allowed-To-Delegate-To',
    '693f2006-5764-3d4a-8439-58f04aab4b59': 'ms-DS-Applies-To-Resource-Types',
    'e185d243-f6ce-4adb-b496-b0c005d7823c': 'ms-DS-Approx-Immed-Subordinates',
    'a34f983b-84c6-4f0c-9050-a3a14a1d35a4': 'ms-DS-Approximate-Last-Logon-Time-Stamp',
    'b87a0ad8-54f7-49c1-84a0-e64d12853588': 'ms-DS-Assigned-AuthN-Policy',
    '2d131b3c-d39f-4aee-815e-8db4bc1ce7ac': 'ms-DS-Assigned-AuthN-Policy-BL',
    'b23fc141-0df5-4aea-b33d-6cf493077b3f': 'ms-DS-Assigned-AuthN-Policy-Silo',
    '33140514-f57a-47d2-8ec4-04c4666600c7': 'ms-DS-Assigned-AuthN-Policy-Silo-BL',
    '3e1ee99c-6604-4489-89d9-84798a89515a': 'ms-DS-AuthenticatedAt-DC',
    'e8b2c971-a6df-47bc-8d6f-62770d527aa5': 'ms-DS-AuthenticatedTo-Accountlist',
    '7a560cc2-ec45-44ba-b2d7-21236ad59fd5': 'ms-DS-AuthN-Policy-Enforced',
    'f2f51102-6be0-493d-8726-1546cdbc8771': 'ms-DS-AuthN-Policy-Silo-Enforced',
    '164d1e05-48a6-4886-a8e9-77a2006e3c77': 'ms-DS-AuthN-Policy-Silo-Members',
    '11fccbc7-fbe4-4951-b4b7-addf6f9efd44': 'ms-DS-AuthN-Policy-Silo-Members-BL',
    'c4af1073-ee50-4be0-b8c0-89a41fe99abe': 'ms-DS-Auxiliary-Classes',
    '503fc3e8-1cc6-461a-99a3-9eee04f402a7': 'ms-DS-Az-Application-Data',
    'db5b0728-6208-4876-83b7-95d3e5695275': 'ms-DS-Az-Application-Name',
    '7184a120-3ac4-47ae-848f-fe0ab20784d4': 'ms-DS-Az-Application-Version',
    '33d41ea8-c0c9-4c92-9494-f104878413fd': 'ms-DS-Az-Biz-Rule',
    '52994b56-0e6c-4e07-aa5c-ef9d7f5a0e25': 'ms-DS-Az-Biz-Rule-Language',
    '013a7277-5c2d-49ef-a7de-b765b36a3f6f': 'ms-DS-Az-Class-ID',
    '6448f56a-ca70-4e2e-b0af-d20e4ce653d0': 'ms-DS-Az-Domain-Timeout',
    'f90abab0-186c-4418-bb85-88447c87222a': 'ms-DS-Az-Generate-Audits',
    'b5f7e349-7a5b-407c-a334-a31c3f538b98': 'ms-DS-Az-Generic-Data',
    '665acb5c-bb92-4dbc-8c59-b3638eab09b3': 'ms-DS-Az-Last-Imported-Biz-Rule-Path',
    '5e53368b-fc94-45c8-9d7d-daf31ee7112d': 'ms-DS-Az-LDAP-Query',
    'cfb9adb7-c4b7-4059-9568-1ed9db6b7248': 'ms-DS-Az-Major-Version',
    'ee85ed93-b209-4788-8165-e702f51bfbf3': 'ms-DS-Az-Minor-Version',
    '8491e548-6c38-4365-a732-af041569b02c': 'ms-DS-Az-Object-Guid',
    'a5f3b553-5d76-4cbe-ba3f-4312152cab18': 'ms-DS-Az-Operation-ID',
    '515a6b06-2617-4173-8099-d5605df043c6': 'ms-DS-Az-Scope-Name',
    '2629f66a-1f95-4bf3-a296-8e9d7b9e30c8': 'ms-DS-Az-Script-Engine-Cache-Max',
    '87d0fb41-2c8b-41f6-b972-11fdfd50d6b0': 'ms-DS-Az-Script-Timeout',
    '7b078544-6c82-4fe9-872f-ff48ad2b2e26': 'ms-DS-Az-Task-Is-Role-Definition',
    'd31a8757-2447-4545-8081-3bb610cacbf2': 'ms-DS-Behavior-Version',
    '3ced1465-7b71-2541-8780-1e1ea6243a82': 'ms-DS-BridgeHead-Servers-Used',
    'f0d8972e-dd5b-40e5-a51d-044c7c17ece7': 'ms-DS-Byte-Array',
    '69cab008-cdd4-4bc9-bab8-0ff37efe1b20': 'ms-DS-Cached-Membership',
    '3566bf1f-beee-4dcb-8abe-ef89fcfec6c1': 'ms-DS-Cached-Membership-Time-Stamp',
    'eebc123e-bae6-4166-9e5b-29884a8b76b0': 'ms-DS-Claim-Attribute-Source',
    'cd789fb9-96b4-4648-8219-ca378161af38': 'ms-DS-Claim-Is-Single-Valued',
    '0c2ce4c7-f1c3-4482-8578-c60d4bb74422': 'ms-DS-Claim-Is-Value-Space-Restricted',
    '2e28edee-ed7c-453f-afe4-93bd86f2174f': 'ms-DS-Claim-Possible-Values',
    '52c8d13a-ce0b-4f57-892b-18f5a43a2400': 'ms-DS-Claim-Shares-Possible-Values-With',
    '54d522db-ec95-48f5-9bbd-1880ebbb2180': 'ms-DS-Claim-Shares-Possible-Values-With-BL',
    'fa32f2a6-f28b-47d0-bf91-663e8f910a72': 'ms-DS-Claim-Source',
    '92f19c05-8dfa-4222-bbd1-2c4f01487754': 'ms-DS-Claim-Source-Type',
    '6afb0e4c-d876-437c-aeb6-c3e41454c272': 'ms-DS-Claim-Type-Applies-To-Class',
    'c66217b9-e48e-47f7-b7d5-6552b8afd619': 'ms-DS-Claim-Value-Type',
    '78565e80-03d4-4fe3-afac-8c3bca2f3653': 'ms-DS-Cloud-Anchor',
    '89848328-7c4e-4f6f-a013-28ce3ad282dc': 'ms-DS-Cloud-IsEnabled',
    '5315ba8e-958f-4b52-bd38-1349a304dd63': 'ms-DS-Cloud-IsManaged',
    'a1e8b54f-4bd6-4fd2-98e2-bcee92a55497': 'ms-DS-Cloud-Issuer-Public-Certificates',
    '9709eaaf-49da-4db2-908a-0446e5eab844': 'ms-DS-cloudExtensionAttribute1',
    '670afcb3-13bd-47fc-90b3-0a527ed81ab7': 'ms-DS-cloudExtensionAttribute10',
    '9e9ebbc8-7da5-42a6-8925-244e12a56e24': 'ms-DS-cloudExtensionAttribute11',
    '3c01c43d-e10b-4fca-92b2-4cf615d5b09a': 'ms-DS-cloudExtensionAttribute12',
    '28be464b-ab90-4b79-a6b0-df437431d036': 'ms-DS-cloudExtensionAttribute13',
    'cebcb6ba-6e80-4927-8560-98feca086a9f': 'ms-DS-cloudExtensionAttribute14',
    'aae4d537-8af0-4daa-9cc6-62eadb84ff03': 'ms-DS-cloudExtensionAttribute15',
    '9581215b-5196-4053-a11e-6ffcafc62c4d': 'ms-DS-cloudExtensionAttribute16',
    '3d3c6dda-6be8-4229-967e-2ff5bb93b4ce': 'ms-DS-cloudExtensionAttribute17',
    '88e73b34-0aa6-4469-9842-6eb01b32a5b5': 'ms-DS-cloudExtensionAttribute18',
    '0975fe99-9607-468a-8e18-c800d3387395': 'ms-DS-cloudExtensionAttribute19',
    'f34ee0ac-c0c1-4ba9-82c9-1a90752f16a5': 'ms-DS-cloudExtensionAttribute2',
    'f5446328-8b6e-498d-95a8-211748d5acdc': 'ms-DS-cloudExtensionAttribute20',
    '82f6c81a-fada-4a0d-b0f7-706d46838eb5': 'ms-DS-cloudExtensionAttribute3',
    '9cbf3437-4e6e-485b-b291-22b02554273f': 'ms-DS-cloudExtensionAttribute4',
    '2915e85b-e347-4852-aabb-22e5a651c864': 'ms-DS-cloudExtensionAttribute5',
    '60452679-28e1-4bec-ace3-712833361456': 'ms-DS-cloudExtensionAttribute6',
    '4a7c1319-e34e-40c2-9d00-60ff7890f207': 'ms-DS-cloudExtensionAttribute7',
    '3cd1c514-8449-44ca-81c0-021781800d2a': 'ms-DS-cloudExtensionAttribute8',
    '0a63e12c-3040-4441-ae26-cd95af0d247e': 'ms-DS-cloudExtensionAttribute9',
    '105babe9-077e-4793-b974-ef0410b62573': 'ms-DS-Computer-Allowed-To-Authenticate-To',
    'afb863c9-bea3-440f-a9f3-6153cc668929': 'ms-DS-Computer-AuthN-Policy',
    '2bef6232-30a1-457e-8604-7af6dbf131b8': 'ms-DS-Computer-AuthN-Policy-BL',
    'dffbd720-0872-402e-9940-fcd78db049ba': 'ms-DS-Computer-SID',
    '2e937524-dfb9-4cac-a436-a5b7da64fd66': 'ms-DS-Computer-TGT-Lifetime',
    '178b7bc2-b63a-11d2-90e1-00c04fd91ab1': 'MS-DS-Consistency-Child-Count',
    '23773dc2-b63a-11d2-90e1-00c04fd91ab1': 'MS-DS-Consistency-Guid',
    'c5e60132-1480-11d3-91c1-0000f87a57d4': 'MS-DS-Creator-SID',
    'b6e5e988-e5e4-4c86-a2ae-0dacb970a0e1': 'ms-DS-Custom-Key-Information',
    '234fcbd8-fb52-4908-a328-fd9f6e58e403': 'ms-DS-Date-Time',
    '6818f726-674b-441b-8a3a-f40596374cea': 'ms-DS-Default-Quota',
    'a9b38cb6-189a-4def-8a70-0fcfa158148e': 'ms-DS-Deleted-Object-Lifetime',
    '642c1129-3899-4721-8e21-4839e3988ce5': 'ms-DS-Device-DN',
    'c30181c7-6342-41fb-b279-f7c566cbe0a7': 'ms-DS-Device-ID',
    'e3fb56c8-5de8-45f5-b1b1-d2b6cd31e762': 'ms-DS-Device-Location',
    'f60a8f96-57c4-422c-a3ad-9e2fa09ce6f7': 'ms-DS-Device-MDMStatus',
    'ef65695a-f179-4e6a-93de-b01e06681cfb': 'ms-DS-Device-Object-Version',
    '100e454d-f3bb-4dcb-845f-8d5edc471c59': 'ms-DS-Device-OS-Type',
    '70fb8c63-5fab-4504-ab9d-14b329a8a7f8': 'ms-DS-Device-OS-Version',
    '90615414-a2a0-4447-a993-53409599b74e': 'ms-DS-Device-Physical-IDs',
    'c4a46807-6adc-4bbb-97de-6bed181a1bfe': 'ms-DS-Device-Trust-Type',
    '2143acca-eead-4d29-b591-85fa49ce9173': 'ms-DS-DnsRootAlias',
    '6055f766-202e-49cd-a8be-e52bb159edfb': 'ms-DS-Drs-Farm-ID',
    'c137427e-9a73-b040-9190-1b095bb43288': 'ms-DS-Egress-Claims-Transformation-Policy',
    '5706aeaf-b940-4fb2-bcfc-5268683ad9fe': 'ms-DS-Enabled-Feature',
    'ce5b01bc-17c6-44b8-9dc1-a9668b00901b': 'ms-DS-Enabled-Feature-BL',
    'e1e9bad7-c6dd-4101-a843-794cec85b038': 'ms-DS-Entry-Time-To-Die',
    '9d054a5a-d187-46c1-9d85-42dfc44a56dd': 'ms-DS-ExecuteScriptPassword',
    '3417ab48-df24-4fb1-80b0-0fcb367e25e3': 'ms-DS-Expire-Passwords-On-Smart-Card-Only-Accounts',
    'bd29bf90-66ad-40e1-887b-10df070419a6': 'ms-DS-External-Directory-Object-Id',
    'b92fd528-38ac-40d4-818d-0433380837c1': 'ms-DS-External-Key',
    '604877cd-9cdb-47c7-b03d-3daadb044910': 'ms-DS-External-Store',
    'dc3ca86f-70ad-4960-8425-a4d6313d93dd': 'ms-DS-Failed-Interactive-Logon-Count',
    'c5d234e5-644a-4403-a665-e26e0aef5e98': 'ms-DS-Failed-Interactive-Logon-Count-At-Last-Successful-Logon',
    'fb00dcdf-ac37-483a-9c12-ac53a6603033': 'ms-DS-Filter-Containers',
    '1e5d393d-8cb7-4b4f-840a-973b36cc09c3': 'ms-DS-Generation-Id',
    'a11703b7-5641-4d9c-863e-5fb3325e74e0': 'ms-DS-GeoCoordinates-Altitude',
    'dc66d44e-3d43-40f5-85c5-3c12e169927e': 'ms-DS-GeoCoordinates-Latitude',
    '94c42110-bae4-4cea-8577-af813af5da25': 'ms-DS-GeoCoordinates-Longitude',
    '888eedd6-ce04-df40-b462-b8a50e41ba38': 'ms-DS-GroupMSAMembership',
    'def449f1-fd3b-4045-98cf-d9658da788b5': 'ms-DS-HAB-Seniority-Index',
    '6f17e347-a842-4498-b8b3-15e007da4fed': 'ms-DS-Has-Domain-NCs',
    '1d3c2d18-42d0-4868-99fe-0eca1e6fa9f3': 'ms-DS-Has-Full-Replica-NCs',
    '11e9a5bc-4517-4049-af9c-51554fb0fc09': 'ms-DS-Has-Instantiated-NCs',
    'ae2de0e2-59d7-4d47-8d47-ed4dfe4357ad': 'ms-DS-Has-Master-NCs',
    '80641043-15a2-40e1-92a2-8ca866f70776': 'ms-DS-Host-Service-Account',
    '79abe4eb-88f3-48e7-89d6-f4bc7e98c331': 'ms-DS-Host-Service-Account-BL',
    '86284c08-0c6e-1540-8b15-75147d23d20d': 'ms-DS-Ingress-Claims-Transformation-Policy',
    '7bc64cea-c04e-4318-b102-3e0729371a65': 'ms-DS-Integer',
    'bc60096a-1b47-4b30-8877-602c93f56532': 'ms-DS-IntId',
    '59527d0f-b7c0-4ce2-a1dd-71cef6963292': 'ms-DS-Is-Compliant',
    'ff155a2a-44e5-4de0-8318-13a58988de4f': 'ms-DS-Is-Domain-For',
    '22a95c0e-1f83-4c82-94ce-bea688cfc871': 'ms-DS-Is-Enabled',
    'c8bc72e0-a6b4-48f0-94a5-fd76a88c9987': 'ms-DS-Is-Full-Replica-For',
    '862166b6-c941-4727-9565-48bfff2941de': 'ms-DS-Is-Member-Of-DL-Transitive',
    '37c94ff6-c6d4-498f-b2f9-c6f7f8647809': 'ms-DS-Is-Partial-Replica-For',
    '6fabdcda-8c53-204f-b1a4-9df0c67c1eb4': 'ms-DS-Is-Possible-Values-Present',
    '998c06ac-3f87-444e-a5df-11b03dc8a50c': 'ms-DS-Is-Primary-Computer-For',
    '51c9f89d-4730-468d-a2b5-1d493212d17e': 'ms-DS-Is-Used-As-Resource-Security-Attribute',
    'fe01245a-341f-4556-951f-48c033a89050': 'ms-DS-Is-User-Cachable-At-Rodc',
    '1df5cf33-0fe5-499e-90e1-e94b42718a46': 'ms-DS-isGC',
    '60686ace-6c27-43de-a4e5-f00c2f8d3309': 'ms-DS-IsManaged',
    'a8e8aa23-3e67-4af1-9d7a-2f1a1d633ac9': 'ms-DS-isRODC',
    '6b3d6fda-0893-43c4-89fb-1fb52a6616a9': 'ms-DS-Issuer-Certificates',
    'b5f1edfe-b4d2-4076-ab0f-6148342b0bf6': 'ms-DS-Issuer-Public-Certificates',
    '649ac98d-9b9a-4d41-af6b-f616f2a62e4a': 'ms-DS-Key-Approximate-Last-Logon-Time-Stamp',
    '5b47d60f-6090-40b2-9f37-2a4de88f3063': 'ms-DS-Key-Credential-Link',
    '938ad788-225f-4eee-93b9-ad24a159e1db': 'ms-DS-Key-Credential-Link-BL',
    'c294f84b-2fad-4b71-be4c-9fc5701f60ba': 'ms-DS-Key-Id',
    'a12e0e9f-dedb-4f31-8f21-1311b958182f': 'ms-DS-Key-Material',
    'bd61253b-9401-4139-a693-356fc400f3ea': 'ms-DS-Key-Principal',
    'd1328fbc-8574-4150-881d-0b1088827878': 'ms-DS-Key-Principal-BL',
    'de71b44c-29ba-4597-9eca-c3348ace1917': 'ms-DS-Key-Usage',
    'c523e9c0-33b5-4ac8-8923-b57b927f42f6': 'ms-DS-KeyVersionNumber',
    '778ff5c9-6f4e-4b74-856a-d68383313910': 'ms-DS-KrbTgt-Link',
    '5dd68c41-bfdf-438b-9b5d-39d9618bf260': 'ms-DS-KrbTgt-Link-BL',
    'c7e7dafa-10c3-4b8b-9acd-54f11063742e': 'ms-DS-Last-Failed-Interactive-Logon-Time',
    '8ab15858-683e-466d-877f-d640e1f9a611': 'ms-DS-Last-Known-RDN',
    '011929e6-8b5d-4258-b64a-00b0b4949747': 'ms-DS-Last-Successful-Interactive-Logon-Time',
    '94f2800c-531f-4aeb-975d-48ac39fd8ca4': 'ms-DS-Local-Effective-Deletion-Time',
    '4ad6016b-b0d2-4c9b-93b6-5964b17b968c': 'ms-DS-Local-Effective-Recycle-Time',
    '421f889a-472e-4fe4-8eb9-e1d0bc6071b2': 'ms-DS-Lockout-Duration',
    'b05bda89-76af-468a-b892-1be55558ecc8': 'ms-DS-Lockout-Observation-Window',
    'b8c8c35e-4a19-4a95-99d0-69fe4446286f': 'ms-DS-Lockout-Threshold',
    'ad7940f8-e43a-4a42-83bc-d688e59ea605': 'ms-DS-Logon-Time-Sync-Interval',
    'd064fb68-1480-11d3-91c1-0000f87a57d4': 'MS-DS-Machine-Account-Quota',
    'e362ed86-b728-0842-b27d-2dea7a9df218': 'ms-DS-ManagedPassword',
    '0e78295a-c6d3-0a40-b491-d62251ffa0a6': 'ms-DS-ManagedPasswordId',
    'f8758ef7-ac76-8843-a2ee-a26b4dcaf409': 'ms-DS-ManagedPasswordInterval',
    'd0d62131-2d4a-d04f-99d9-1c63646229a4': 'ms-DS-ManagedPasswordPreviousId',
    '60234769-4819-4615-a1b2-49d2f119acb5': 'ms-DS-Mastered-By',
    'd1e169a4-ebe9-49bf-8fcb-8aef3874592d': 'ms-DS-Max-Values',
    'fdd337f5-4999-4fce-b252-8ff9c9b43875': 'ms-DS-Maximum-Password-Age',
    '0a5caa39-05e6-49ca-b808-025b936610e7': 'ms-DS-Maximum-Registration-Inactivity-Period',
    'e215395b-9104-44d9-b894-399ec9e21dfc': 'ms-DS-Member-Transitive',
    'cbf7e6cd-85a4-4314-8939-8bfe80597835': 'ms-DS-Members-For-Az-Role',
    'ececcd20-a7e0-4688-9ccf-02ece5e287f5': 'ms-DS-Members-For-Az-Role-BL',
    '4d371c11-4cad-4c41-8ad2-b180ab2bd13c': 'ms-DS-Members-Of-Resource-Property-List',
    '7469b704-edb0-4568-a5a5-59f4862c75a7': 'ms-DS-Members-Of-Resource-Property-List-BL',
    '2a74f878-4d9c-49f9-97b3-6767d1cbd9a3': 'ms-DS-Minimum-Password-Age',
    'b21b3439-4c3a-441c-bb5f-08f20e9b315e': 'ms-DS-Minimum-Password-Length',
    '8a167ce4-f9e8-47eb-8d78-f7fe80abb2cc': 'ms-DS-NC-Repl-Cursors',
    '9edba85a-3e9e-431b-9b1a-a5b6e9eda796': 'ms-DS-NC-Repl-Inbound-Neighbors',
    '855f2ef5-a1c5-4cc4-ba6d-32522848b61f': 'ms-DS-NC-Repl-Outbound-Neighbors',
    '97de9615-b537-46bc-ac0f-10720f3909f3': 'ms-DS-NC-Replica-Locations',
    '3df793df-9858-4417-a701-735a1ecebf74': 'ms-DS-NC-RO-Replica-Locations',
    'f547511c-5b2a-44cc-8358-992a88258164': 'ms-DS-NC-RO-Replica-Locations-BL',
    '5a2eacd7-cc2b-48cf-9d9a-b6f1a0024de9': 'ms-DS-NC-Type',
    '15585999-fd49-4d66-b25d-eeb96aba8174': 'ms-DS-Never-Reveal-Group',
    'cafcb1de-f23c-46b5-adf7-1e64957bd5db': 'ms-DS-Non-Members',
    '2a8c68fc-3a7a-4e87-8720-fe77c51cbe74': 'ms-DS-Non-Members-BL',
    '2de144fc-1f52-486f-bdf4-16fcc3084e54': 'ms-DS-Non-Security-Group-Extra-Classes',
    '638ec2e8-22e7-409c-85d2-11b21bee72de': 'ms-DS-Object-Reference',
    '2b702515-c1f7-4b3b-b148-c0e4c6ceecb4': 'ms-DS-Object-Reference-BL',
    '34f6bdf5-2e79-4c3b-8e14-3d93b75aab89': 'ms-DS-Object-SOA',
    'f9c9a57c-3941-438d-bebf-0edaf2aca187': 'ms-DS-OIDToGroup-Link',
    '1a3d0d20-5844-4199-ad25-0f5039a76ada': 'ms-DS-OIDToGroup-Link-BL',
    '93f701be-fa4c-43b6-bc2f-4dbea718ffab': 'ms-DS-Operations-For-Az-Role',
    'f85b6228-3734-4525-b6b7-3f3bb220902c': 'ms-DS-Operations-For-Az-Role-BL',
    '1aacb436-2e9d-44a9-9298-ce4debeb6ebf': 'ms-DS-Operations-For-Az-Task',
    'a637d211-5739-4ed1-89b2-88974548bc59': 'ms-DS-Operations-For-Az-Task-BL',
    '8a0560c1-97b9-4811-9db7-dc061598965b': 'ms-DS-Optional-Feature-Flags',
    '9b88bda8-dd82-4998-a91d-5f2d2baf1927': 'ms-DS-Optional-Feature-GUID',
    '79d2f34c-9d7d-42bb-838f-866b3e4400e2': 'ms-DS-Other-Settings',
    'b918fe7d-971a-f404-9e21-9261abec970b': 'ms-DS-Parent-Dist-Name',
    'db68054b-c9c3-4bf0-b15b-0fb52552a610': 'ms-DS-Password-Complexity-Enabled',
    'fed81bb7-768c-4c2f-9641-2245de34794d': 'ms-DS-Password-History-Length',
    '75ccdd8f-af6c-4487-bb4b-69e4d38a959c': 'ms-DS-Password-Reversible-Encryption-Enabled',
    '456374ac-1f0a-4617-93cf-bc55a7c9d341': 'ms-DS-Password-Settings-Precedence',
    'd161adf0-ca24-4993-a3aa-8b2c981302e8': 'MS-DS-Per-User-Trust-Quota',
    '8b70a6c6-50f9-4fa3-a71e-1ce03040449b': 'MS-DS-Per-User-Trust-Tombstones-Quota',
    '5bd5208d-e5f4-46ae-a514-543bc9c47659': 'ms-DS-Phonetic-Company-Name',
    '6cd53daf-003e-49e7-a702-6fa896e7a6ef': 'ms-DS-Phonetic-Department',
    'e21a94e4-2d66-4ce5-b30d-0ef87a776ff0': 'ms-DS-Phonetic-Display-Name',
    '4b1cba4e-302f-4134-ac7c-f01f6c797843': 'ms-DS-Phonetic-First-Name',
    'f217e4ec-0836-4b90-88af-2f5d4bbda2bc': 'ms-DS-Phonetic-Last-Name',
    'fa0c8ade-4c94-4610-bace-180efdee2140': 'ms-DS-Preferred-Data-Location',
    'd921b50a-0ab2-42cd-87f6-09cf83a91854': 'ms-DS-Preferred-GC-Site',
    'a13df4e2-dbb0-4ceb-828b-8b2e143e9e81': 'ms-DS-Primary-Computer',
    '564e9325-d057-c143-9e3b-4f9e5ef46f93': 'ms-DS-Principal-Name',
    'c881b4e2-43c0-4ebe-b9bb-5250aa9b434c': 'ms-DS-Promotion-Settings',
    '5e6cf031-bda8-43c8-aca4-8fee4127005b': 'ms-DS-PSO-Applied',
    '64c80f48-cdd2-4881-a86d-4e97b6f561fc': 'ms-DS-PSO-Applies-To',
    'fbb9a00d-3a8c-4233-9cf9-7189264903a1': 'ms-DS-Quota-Amount',
    '6655b152-101c-48b4-b347-e1fcebc60157': 'ms-DS-Quota-Effective',
    '16378906-4ea5-49be-a8d1-bfd41dff4f65': 'ms-DS-Quota-Trustee',
    'b5a84308-615d-4bb7-b05f-2f1746aa439f': 'ms-DS-Quota-Used',
    '617626e9-01eb-42cf-991f-ce617982237e': 'ms-DS-Registered-Owner',
    '0449160c-5a8e-4fc8-b052-01c0f6e48f02': 'ms-DS-Registered-Users',
    'ca3286c2-1f64-4079-96bc-e62b610e730f': 'ms-DS-Registration-Quota',
    'd7c53242-724e-4c39-9d4c-2df8c9d66c7a': 'ms-DS-Repl-Attribute-Meta-Data',
    '2f5c8145-e1bd-410b-8957-8bfa81d5acfd': 'ms-DS-Repl-Value-Meta-Data',
    '1e02d2ef-44ad-46b2-a67d-9fd18d780bca': 'ms-DS-Repl-Value-Meta-Data-Ext',
    '0ea12b84-08b3-11d3-91bc-0000f87a57d4': 'MS-DS-Replicates-NC-Reason',
    '85abd4f4-0a89-4e49-bdec-6f35bb2562ba': 'ms-DS-Replication-Notify-First-DSA-Delay',
    'd63db385-dd92-4b52-b1d8-0d3ecc0e86b6': 'ms-DS-Replication-Notify-Subsequent-DSA-Delay',
    '08e3aa79-eb1c-45b5-af7b-8f94246c8e41': 'ms-DS-ReplicationEpoch',
    'eadd3dfe-ae0e-4cc2-b9b9-5fe5b6ed2dd2': 'ms-DS-Required-Domain-Behavior-Version',
    '4beca2e8-a653-41b2-8fee-721575474bec': 'ms-DS-Required-Forest-Behavior-Version',
    'b77ea093-88d0-4780-9a98-911f8e8b1dca': 'ms-DS-Resultant-PSO',
    'd5b35506-19d6-4d26-9afb-11357ac99b5e': 'ms-DS-Retired-Repl-NC-Signatures',
    '303d9f4a-1dd6-4b38-8fc5-33afe8c988ad': 'ms-DS-Reveal-OnDemand-Group',
    '94f6f2ac-c76d-4b5e-b71f-f332c3e93c22': 'ms-DS-Revealed-DSAs',
    'cbdad11c-7fec-387b-6219-3a0627d9af81': 'ms-DS-Revealed-List',
    'aa1c88fd-b0f6-429f-b2ca-9d902266e808': 'ms-DS-Revealed-List-BL',
    '185c7821-3749-443a-bd6a-288899071adb': 'ms-DS-Revealed-Users',
    '24977c8c-c1b7-3340-b4f6-2b375eb711d7': 'ms-DS-RID-Pool-Allocation-Enabled',
    'b39a61be-ed07-4cab-9a4a-4963ed0141e1': 'ms-ds-Schema-Extensions',
    '4c51e316-f628-43a5-b06b-ffb695fcb4f3': 'ms-DS-SD-Reference-Domain',
    'aa156612-2396-467e-ad6a-28d23fdb1865': 'ms-DS-Secondary-KrbTgt-Number',
    '4f146ae8-a4fe-4801-a731-f51848a4f4e4': 'ms-DS-Security-Group-Extra-Classes',
    '278947b9-5222-435e-96b7-1503858c2b48': 'ms-DS-Service-Allowed-NTLM-Network-Authentication',
    '97da709a-3716-4966-b1d1-838ba53c3d89': 'ms-DS-Service-Allowed-To-Authenticate-From',
    'f2973131-9b4d-4820-b4de-0474ef3b849f': 'ms-DS-Service-Allowed-To-Authenticate-To',
    '2a6a6d95-28ce-49ee-bb24-6d1fc01e3111': 'ms-DS-Service-AuthN-Policy',
    '2c1128ec-5aa2-42a3-b32d-f0979ca9fcd2': 'ms-DS-Service-AuthN-Policy-BL',
    '5dfe3c20-ca29-407d-9bab-8421e55eb75c': 'ms-DS-Service-TGT-Lifetime',
    '0e1b47d7-40a3-4b48-8d1b-4cac0c1cdf21': 'ms-DS-Settings',
    '1dcc0722-aab0-4fef-956f-276fe19de107': 'ms-DS-Shadow-Principal-Sid',
    'c17c5602-bcb7-46f0-9656-6370ca884b72': 'ms-DS-Site-Affinity',
    '98a7f36d-3595-448a-9e6f-6b8965baed9c': 'ms-DS-SiteName',
    'b002f407-1340-41eb-bca0-bd7d938e25a9': 'ms-DS-Source-Anchor',
    '773e93af-d3b4-48d4-b3f9-06457602d3d0': 'ms-DS-Source-Object-DN',
    '789ee1eb-8c8e-4e4c-8cec-79b31b7617b5': 'ms-DS-SPN-Suffixes',
    'aacd2170-482a-44c6-b66e-42c2f66a285c': 'ms-DS-Strong-NTLM-Policy',
    '20119867-1d04-4ab7-9371-cfc3d5df0afd': 'ms-DS-Supported-Encryption-Types',
    'b7acc3d2-2a74-4fa4-ac25-e63fe8b61218': 'ms-DS-SyncServerUrl',
    '35319082-8c4a-4646-9386-c2949d49894d': 'ms-DS-Tasks-For-Az-Role',
    'a0dcd536-5158-42fe-8c40-c00a7ad37959': 'ms-DS-Tasks-For-Az-Role-BL',
    'b11c8ee2-5fcd-46a7-95f0-f38333f096cf': 'ms-DS-Tasks-For-Az-Task',
    'df446e52-b5fa-4ca2-a42f-13f98a526c8f': 'ms-DS-Tasks-For-Az-Task-BL',
    'd5006229-9913-2242-8b17-83761d1e0e5b': 'ms-DS-TDO-Egress-BL',
    '5a5661a1-97c6-544b-8056-e430fe7bc554': 'ms-DS-TDO-Ingress-BL',
    '65650576-4699-4fc9-8d18-26e0cd0137a6': 'ms-DS-Token-Group-Names',
    'fa06d1f4-7922-4aad-b79c-b2201f54417c': 'ms-DS-Token-Group-Names-Global-And-Universal',
    '523fc6c8-9af4-4a02-9cd7-3dea129eeb27': 'ms-DS-Token-Group-Names-No-GC-Acceptable',
    '461744d7-f3b6-45ba-8753-fb9552a5df32': 'ms-DS-Tombstone-Quota-Factor',
    '7b7cce4f-f1f5-4bb6-b7eb-23504af19e75': 'ms-DS-Top-Quota-Usage',
    '55872b71-c4b2-3b48-ae51-4095f91ec600': 'ms-DS-Transformation-Rules',
    '0bb49a10-536b-bc4d-a273-0bab0dd4bd10': 'ms-DS-Transformation-Rules-Compiled',
    '29cc866e-49d3-4969-942e-1dbc0925d183': 'ms-DS-Trust-Forest-Trust-Info',
    '146eb639-bb9f-4fc1-a825-e29e00c77920': 'ms-DS-UpdateScript',
    '2cc4b836-b63f-4940-8d23-ea7acf06af56': 'ms-DS-User-Account-Control-Computed',
    '7ece040f-9327-4cdc-aad3-037adfe62639': 'ms-DS-User-Allowed-NTLM-Network-Authentication',
    '2c4c9600-b0e1-447d-8dda-74902257bdb5': 'ms-DS-User-Allowed-To-Authenticate-From',
    'de0caa7f-724e-4286-b179-192671efc664': 'ms-DS-User-Allowed-To-Authenticate-To',
    'cd26b9f3-d415-442a-8f78-7c61523ee95b': 'ms-DS-User-AuthN-Policy',
    '2f17faa9-5d47-4b1f-977e-aa52fabe65c8': 'ms-DS-User-AuthN-Policy-BL',
    'add5cf10-7b09-4449-9ae6-2534148f8a72': 'ms-DS-User-Password-Expiry-Time-Computed',
    '8521c983-f599-420f-b9ab-b1222bdf95c1': 'ms-DS-User-TGT-Lifetime',
    '31f7b8b6-c9f8-4f2d-a37b-58a823030331': 'ms-DS-USN-Last-Sync-Success',
    '78fc5d84-c1dc-3148-8984-58f792d41d3e': 'ms-DS-Value-Type-Reference',
    'ab5543ad-23a1-3b45-b937-9b313d5474a8': 'ms-DS-Value-Type-Reference-BL',
    'a8df7394-c5ea-11d1-bbcb-0080c76670c0': 'ms-Exch-Assistant-Name',
    'a8df7407-c5ea-11d1-bbcb-0080c76670c0': 'ms-Exch-House-Identifier',
    '16775820-47f3-11d1-a9c3-0000f80367c1': 'ms-Exch-LabeledURI',
    'bf9679f4-0de6-11d0-a285-00aa003049e2': 'ms-Exch-Owner-BL',
    '5643ff81-35b6-4ca9-9512-baf0bd0a2772': 'ms-FRS-Hub-Member',
    '92aa27e0-5c50-402d-9ec1-ee847def9788': 'ms-FRS-Topology-Pref',
    '1fd55ea8-88a7-47dc-8129-0daa97186a54': 'ms-FVE-KeyPackage',
    'f76909bc-e678-47a0-b0b3-f86a0044c06d': 'ms-FVE-RecoveryGuid',
    '43061ac1-c8ad-4ccc-b785-2bfac20fc60a': 'ms-FVE-RecoveryPassword',
    '85e5a5cf-dcee-4075-9cfd-ac9db6a2f245': 'ms-FVE-VolumeGuid',
    '0e0d0938-2658-4580-a9f6-7a0ac7b566cb': 'ms-ieee-80211-Data',
    '6558b180-35da-4efe-beed-521f8f48cafb': 'ms-ieee-80211-Data-Type',
    '7f73ef75-14c9-4c23-81de-dd07a06f9e8b': 'ms-ieee-80211-ID',
    '8a5c99e9-2230-46eb-b8e8-e59d712eb9ee': 'ms-IIS-FTP-Dir',
    '2a7827a4-1483-49a5-9d84-52e3812156b4': 'ms-IIS-FTP-Root',
    '8ae70db5-6406-4196-92fe-f3bb557520a7': 'ms-Imaging-Hash-Algorithm',
    '51583ce9-94fa-4b12-b990-304c35b18595': 'ms-Imaging-PSP-Identifier',
    '7b6760ae-d6ed-44a6-b6be-9de62c09ec67': 'ms-Imaging-PSP-String',
    '9cdfdbc5-0304-4569-95f6-c4f663fe5ae6': 'ms-Imaging-Thumbprint-Hash',
    'ae18119f-6390-0045-b32d-97dbc701aef7': 'ms-Kds-CreateTime',
    '96400482-cf07-e94c-90e8-f2efc4f0495e': 'ms-Kds-DomainID',
    'db2c48b2-d14d-ec4e-9f58-ad579d8b440e': 'ms-Kds-KDF-AlgorithmID',
    '8a800772-f4b8-154f-b41c-2e4271eff7a7': 'ms-Kds-KDF-Param',
    '615f42a1-37e7-1148-a0dd-3007e09cfc81': 'ms-Kds-PrivateKey-Length',
    'e338f470-39cd-4549-ab5b-f69f9e583fe0': 'ms-Kds-PublicKey-Length',
    '26627c27-08a2-0a40-a1b1-8dce85b42993': 'ms-Kds-RootKeyData',
    '1702975d-225e-cb4a-b15d-0daea8b5e990': 'ms-Kds-SecretAgreement-AlgorithmID',
    '30b099d9-edfe-7549-b807-eba444da79e9': 'ms-Kds-SecretAgreement-Param',
    'd999b030-feed-4975-b807-eba444da79e9': 'ms-Kds-SecretAgreement-Param!swappedBytes',  # This GUID has been seen in the wild  # noqa
    '6cdc047f-f522-b74a-9a9c-d95ac8cdfda2': 'ms-Kds-UseStartTime',
    'd5f07340-e6b0-1e4a-97be-0d3318bd9db1': 'ms-Kds-Version',
    '9c1495a5-4d76-468e-991e-1433b0a67855': 'ms-net-ieee-80211-GP-PolicyData',
    '35697062-1eaf-448b-ac1e-388e0be4fdee': 'ms-net-ieee-80211-GP-PolicyGUID',
    '0f69c62e-088e-4ff5-a53a-e923cec07c0a': 'ms-net-ieee-80211-GP-PolicyReserved',
    '8398948b-7457-4d91-bd4d-8d7ed669c9f7': 'ms-net-ieee-8023-GP-PolicyData',
    '94a7b05a-b8b2-4f59-9c25-39e69baa1684': 'ms-net-ieee-8023-GP-PolicyGUID',
    'd3c527c7-2606-4deb-8cfd-18426feec8ce': 'ms-net-ieee-8023-GP-PolicyReserved',
    'b8dfa744-31dc-4ef1-ac7c-84baf7ef9da7': 'ms-PKI-AccountCredentials',
    '3164c36a-ba26-468c-8bda-c1e5cc256728': 'ms-PKI-Cert-Template-OID',
    'dbd90548-aa37-4202-9966-8c537ba5ce32': 'ms-PKI-Certificate-Application-Policy',
    'ea1dddc4-60ff-416e-8cc0-17cee534bce7': 'ms-PKI-Certificate-Name-Flag',
    '38942346-cc5b-424b-a7d8-6ffd12029c5f': 'ms-PKI-Certificate-Policy',
    'b7ff5a38-0818-42b0-8110-d3d154c97f24': 'ms-PKI-Credential-Roaming-Tokens',
    'b3f93023-9239-4f7c-b99c-6745d87adbc2': 'ms-PKI-DPAPIMasterKeys',
    'd15ef7d8-f226-46db-ae79-b34e560bd12c': 'ms-PKI-Enrollment-Flag',
    'f22bd38f-a1d0-4832-8b28-0331438886a6': 'ms-PKI-Enrollment-Servers',
    'e96a63f5-417f-46d3-be52-db7703c503df': 'ms-PKI-Minimal-Key-Size',
    '8c9e1288-5028-4f4f-a704-76d026f246ef': 'ms-PKI-OID-Attribute',
    '5f49940e-a79f-4a51-bb6f-3d446a54dc6b': 'ms-PKI-OID-CPS',
    '7d59a816-bb05-4a72-971f-5c1331f67559': 'ms-PKI-OID-LocalizedName',
    '04c4da7a-e114-4e69-88de-e293f2d3b395': 'ms-PKI-OID-User-Notice',
    'bab04ac2-0435-4709-9307-28380e7c7001': 'ms-PKI-Private-Key-Flag',
    '3c91fbbf-4773-4ccd-a87b-85d53e7bcf6a': 'ms-PKI-RA-Application-Policies',
    'd546ae22-0951-4d47-817e-1c9f96faad46': 'ms-PKI-RA-Policies',
    'fe17e04b-937d-4f7e-8e0e-9292c8d5683e': 'ms-PKI-RA-Signature',
    '6617e4ac-a2f1-43ab-b60c-11fbd1facf05': 'ms-PKI-RoamingTimeStamp',
    '0cd8711f-0afc-4926-a4b1-09b08d3d436c': 'ms-PKI-Site-Name',
    '9de8ae7d-7a5b-421d-b5e4-061f79dfd5d7': 'ms-PKI-Supersede-Templates',
    '13f5236c-1884-46b1-b5d0-484e38990d58': 'ms-PKI-Template-Minor-Revision',
    '0c15e9f5-491d-4594-918f-32813a091da9': 'ms-PKI-Template-Schema-Version',
    'a6f24a23-d65c-4d65-a64f-35fb6873c2b9': 'ms-RADIUS-FramedInterfaceId',
    'f63ed610-d67c-494d-87be-cd1e24359a38': 'ms-RADIUS-FramedIpv6Prefix',
    '5a5aa804-3083-4863-94e5-018a79a22ec0': 'ms-RADIUS-FramedIpv6Route',
    'a4da7289-92a3-42e5-b6b6-dad16d280ac9': 'ms-RADIUS-SavedFramedInterfaceId',
    '0965a062-b1e1-403b-b48d-5c0eb0e952cc': 'ms-RADIUS-SavedFramedIpv6Prefix',
    '9666bb5c-df9d-4d41-b437-2eec7e27c9b3': 'ms-RADIUS-SavedFramedIpv6Route',
    'f39b98ad-938d-11d1-aebd-0000f80367c1': 'ms-RRAS-Attribute',
    'f39b98ac-938d-11d1-aebd-0000f80367c1': 'ms-RRAS-Vendor-Attribute-Entry',
    '0353c4b5-d199-40b0-b3c5-deb32fd9ec06': 'ms-SPP-Config-License',
    '6e8797c4-acda-4a49-8740-b0bd05a9b831': 'ms-SPP-Confirmation-Id',
    'a601b091-8652-453a-b386-87ad239b7c08': 'ms-SPP-CSVLK-Partial-Product-Key',
    'b47f510d-6b50-47e1-b556-772c79e4ffc4': 'ms-SPP-CSVLK-Pid',
    '9684f739-7b78-476d-8d74-31ad7692eef4': 'ms-SPP-CSVLK-Sku-Id',
    '69bfb114-407b-4739-a213-c663802b3e37': 'ms-SPP-Installation-Id',
    '1075b3a1-bbaf-49d2-ae8d-c4f25c823303': 'ms-SPP-Issuance-License',
    '9b663eda-3542-46d6-9df0-314025af2bac': 'ms-SPP-KMS-Ids',
    '098f368e-4812-48cd-afb7-a136b96807ed': 'ms-SPP-Online-License',
    '67e4d912-f362-4052-8c79-42f45ba7b221': 'ms-SPP-Phone-License',
    'e0c6baae-ccee-11d2-9993-0000f87a57d4': 'MS-SQL-Alias',
    'db77be4a-ccee-11d2-9993-0000f87a57d4': 'MS-SQL-AllowAnonymousSubscription',
    'c4186b6e-d34b-11d2-999a-0000f87a57d4': 'MS-SQL-AllowImmediateUpdatingSubscription',
    'c3bb7054-d34b-11d2-999a-0000f87a57d4': 'MS-SQL-AllowKnownPullSubscription',
    'c458ca80-d34b-11d2-999a-0000f87a57d4': 'MS-SQL-AllowQueuedUpdatingSubscription',
    'c49b8be8-d34b-11d2-999a-0000f87a57d4': 'MS-SQL-AllowSnapshotFilesFTPDownloading',
    '8fda89f4-ccee-11d2-9993-0000f87a57d4': 'MS-SQL-AppleTalk',
    'fbcda2ea-ccee-11d2-9993-0000f87a57d4': 'MS-SQL-Applications',
    '603e94c4-ccee-11d2-9993-0000f87a57d4': 'MS-SQL-Build',
    '696177a6-ccee-11d2-9993-0000f87a57d4': 'MS-SQL-CharacterSet',
    '7778bd90-ccee-11d2-9993-0000f87a57d4': 'MS-SQL-Clustered',
    'a92d23da-ccee-11d2-9993-0000f87a57d4': 'MS-SQL-ConnectionURL',
    '4f6cbdd8-ccee-11d2-9993-0000f87a57d4': 'MS-SQL-Contact',
    'ede14754-ccee-11d2-9993-0000f87a57d4': 'MS-SQL-CreationDate',
    'd5a0dbdc-ccee-11d2-9993-0000f87a57d4': 'MS-SQL-Database',
    '8386603c-ccef-11d2-9993-0000f87a57d4': 'MS-SQL-Description',
    'bcdd4f0e-ccee-11d2-9993-0000f87a57d4': 'MS-SQL-GPSHeight',
    'b222ba0e-ccee-11d2-9993-0000f87a57d4': 'MS-SQL-GPSLatitude',
    'b7577c94-ccee-11d2-9993-0000f87a57d4': 'MS-SQL-GPSLongitude',
    'd0aedb2e-ccee-11d2-9993-0000f87a57d4': 'MS-SQL-InformationDirectory',
    'a42cd510-ccee-11d2-9993-0000f87a57d4': 'MS-SQL-InformationURL',
    '01e9a98a-ccef-11d2-9993-0000f87a57d4': 'MS-SQL-Keywords',
    'c57f72f4-ccee-11d2-9993-0000f87a57d4': 'MS-SQL-Language',
    'f2b6abca-ccee-11d2-9993-0000f87a57d4': 'MS-SQL-LastBackupDate',
    'f6d6dd88-ccee-11d2-9993-0000f87a57d4': 'MS-SQL-LastDiagnosticDate',
    '9fcc43d4-ccee-11d2-9993-0000f87a57d4': 'MS-SQL-LastUpdatedDate',
    '561c9644-ccee-11d2-9993-0000f87a57d4': 'MS-SQL-Location',
    '5b5d448c-ccee-11d2-9993-0000f87a57d4': 'MS-SQL-Memory',
    '8157fa38-ccee-11d2-9993-0000f87a57d4': 'MS-SQL-MultiProtocol',
    '3532dfd8-ccee-11d2-9993-0000f87a57d4': 'MS-SQL-Name',
    '7b91c840-ccee-11d2-9993-0000f87a57d4': 'MS-SQL-NamedPipe',
    'ae0c11b8-ccee-11d2-9993-0000f87a57d4': 'MS-SQL-PublicationURL',
    'c1676858-d34b-11d2-999a-0000f87a57d4': 'MS-SQL-Publisher',
    '48fd44ea-ccee-11d2-9993-0000f87a57d4': 'MS-SQL-RegisteredOwner',
    '64933a3e-ccee-11d2-9993-0000f87a57d4': 'MS-SQL-ServiceAccount',
    'e9098084-ccee-11d2-9993-0000f87a57d4': 'MS-SQL-Size',
    '6ddc42c0-ccee-11d2-9993-0000f87a57d4': 'MS-SQL-SortOrder',
    '86b08004-ccee-11d2-9993-0000f87a57d4': 'MS-SQL-SPX',
    '9a7d4770-ccee-11d2-9993-0000f87a57d4': 'MS-SQL-Status',
    '8ac263a6-ccee-11d2-9993-0000f87a57d4': 'MS-SQL-TCPIP',
    'c4e311fc-d34b-11d2-999a-0000f87a57d4': 'MS-SQL-ThirdParty',
    'ca48eba8-ccee-11d2-9993-0000f87a57d4': 'MS-SQL-Type',
    '72dc918a-ccee-11d2-9993-0000f87a57d4': 'MS-SQL-UnicodeSortOrder',
    'c07cc1d0-ccee-11d2-9993-0000f87a57d4': 'MS-SQL-Version',
    '94c56394-ccee-11d2-9993-0000f87a57d4': 'MS-SQL-Vines',
    '4cc4601e-7201-4141-abc8-3e529ae88863': 'ms-TAPI-Conference-Blob',
    'efd7d7f7-178e-4767-87fa-f8a16b840544': 'ms-TAPI-Ip-Address',
    '89c1ebcf-7a5f-41fd-99ca-c900b32299ab': 'ms-TAPI-Protocol-Id',
    '70a4e7ea-b3b9-4643-8918-e6dd2471bfd4': 'ms-TAPI-Unique-Identifier',
    'c894809d-b513-4ff8-8811-f4f43f5ac7bc': 'ms-TPM-Owner-Information-Temp',
    'aa4e1a6d-550d-4e05-8c35-4afcb917a9fe': 'ms-TPM-OwnerInformation',
    '19d706eb-4d76-44a2-85d6-1c342be3be37': 'ms-TPM-Srk-Pub-Thumbprint',
    'ea1b7b93-5e48-46d5-bc6c-4df4fda78a35': 'ms-TPM-Tpm-Information-For-Computer',
    '14fa84c9-8ecd-4348-bc91-6d3ced472ab7': 'ms-TPM-Tpm-Information-For-Computer-BL',
    '3a0cd464-bc54-40e7-93ae-a646a6ecc4b4': 'ms-TS-Allow-Logon',
    '1cf41bba-5604-463e-94d6-1a1287b72ca3': 'ms-TS-Broken-Connection-Action',
    '23572aaf-29dd-44ea-b0fa-7e8438b9a4a3': 'ms-TS-Connect-Client-Drives',
    '8ce6a937-871b-4c92-b285-d99d4036681c': 'ms-TS-Connect-Printer-Drives',
    'c0ffe2bd-cacf-4dc7-88d5-61e9e95766f6': 'ms-TS-Default-To-Main-Printer',
    '40e1c407-4344-40f3-ab43-3625a34a63a2': 'ms-TS-Endpoint-Data',
    '3c08b569-801f-4158-b17b-e363d6ae696a': 'ms-TS-Endpoint-Plugin',
    '377ade80-e2d8-46c5-9bcd-6d9dec93b35e': 'ms-TS-Endpoint-Type',
    '70004ef5-25c3-446a-97c8-996ae8566776': 'MS-TS-ExpireDate',
    '54dfcf71-bc3f-4f0b-9d5a-4b2476bb8925': 'MS-TS-ExpireDate2',
    '41bc7f04-be72-4930-bd10-1f3439412387': 'MS-TS-ExpireDate3',
    '5e11dc43-204a-4faf-a008-6863621c6f5f': 'MS-TS-ExpireDate4',
    '5d3510f0-c4e7-4122-b91f-a20add90e246': 'ms-TS-Home-Directory',
    '5f0a24d9-dffa-4cd9-acbf-a0680c03731e': 'ms-TS-Home-Drive',
    '9201ac6f-1d69-4dfb-802e-d95510109599': 'ms-TS-Initial-Program',
    '0ae94a89-372f-4df2-ae8a-c64a2bc47278': 'MS-TS-LicenseVersion',
    '4b0df103-8d97-45d9-ad69-85c3080ba4e7': 'MS-TS-LicenseVersion2',
    'f8ba8f81-4cab-4973-a3c8-3a6da62a5e31': 'MS-TS-LicenseVersion3',
    '70ca5d97-2304-490a-8a27-52678c8d2095': 'MS-TS-LicenseVersion4',
    'f3bcc547-85b0-432c-9ac0-304506bf2c83': 'MS-TS-ManagingLS',
    '349f0757-51bd-4fc8-9d66-3eceea8a25be': 'MS-TS-ManagingLS2',
    'fad5dcc1-2130-4c87-a118-75322cd67050': 'MS-TS-ManagingLS3',
    'f7a3b6a0-2107-4140-b306-75cb521731e5': 'MS-TS-ManagingLS4',
    '1d960ee2-6464-4e95-a781-e3b5cd5f9588': 'ms-TS-Max-Connection-Time',
    '326f7089-53d8-4784-b814-46d8535110d2': 'ms-TS-Max-Disconnection-Time',
    'ff739e9c-6bb7-460e-b221-e250f3de0f95': 'ms-TS-Max-Idle-Time',
    '29259694-09e4-4237-9f72-9306ebe63ab2': 'ms-TS-Primary-Desktop',
    '9daadc18-40d1-4ed1-a2bf-6b9bf47d3daa': 'ms-TS-Primary-Desktop-BL',
    'e65c30db-316c-4060-a3a0-387b083f09cd': 'ms-TS-Profile-Path',
    'faaea977-9655-49d7-853d-f27bb7aaca0f': 'MS-TS-Property01',
    '3586f6ac-51b7-4978-ab42-f936463198e7': 'MS-TS-Property02',
    '366ed7ca-3e18-4c7f-abae-351a01e4b4f7': 'ms-TS-Reconnection-Action',
    '15177226-8642-468b-8c48-03ddfd004982': 'ms-TS-Remote-Control',
    '34b107af-a00a-455a-b139-dd1a1b12d8af': 'ms-TS-Secondary-Desktop-BL',
    'f63aa29a-bb31-48e1-bfab-0a6c5a1d39c2': 'ms-TS-Secondary-Desktops',
    'a744f666-3d3c-4cc8-834b-9d4f6f687b8b': 'ms-TS-Work-Directory',
    '87e53590-971d-4a52-955b-4794d15a84ae': 'MS-TSLS-Property01',
    '47c77bb0-316e-4e2f-97f1-0d4c48fca9dd': 'MS-TSLS-Property02',
    '6366c0c1-6972-4e66-b3a5-1d52ad0c0547': 'ms-WMI-Author',
    'f9cdf7a0-ec44-4937-a79b-cd91522b3aa8': 'ms-WMI-ChangeDate',
    '90c1925f-4a24-4b07-b202-be32eb3c8b74': 'ms-WMI-Class',
    '2b9c0ebc-c272-45cb-99d2-4d0e691632e0': 'ms-WMI-ClassDefinition',
    '748b0a2e-3351-4b3f-b171-2f17414ea779': 'ms-WMI-CreationDate',
    '50c8673a-8f56-4614-9308-9e1340fb9af3': 'ms-WMI-Genus',
    '9339a803-94b8-47f7-9123-a853b9ff7e45': 'ms-WMI-ID',
    'f4d8085a-8c5b-4785-959b-dc585566e445': 'ms-WMI-int8Default',
    'e3d8b547-003d-4946-a32b-dc7cedc96b74': 'ms-WMI-int8Max',
    'ed1489d1-54cc-4066-b368-a00daa2664f1': 'ms-WMI-int8Min',
    '103519a9-c002-441b-981a-b0b3e012c803': 'ms-WMI-int8ValidValues',
    '1b0c07f8-76dd-4060-a1e1-70084619dc90': 'ms-WMI-intDefault',
    '18e006b9-6445-48e3-9dcf-b5ecfbc4df8e': 'ms-WMI-intFlags1',
    '075a42c9-c55a-45b1-ac93-eb086b31f610': 'ms-WMI-intFlags2',
    'f29fa736-de09-4be4-b23a-e734c124bacc': 'ms-WMI-intFlags3',
    'bd74a7ac-c493-4c9c-bdfa-5c7b119ca6b2': 'ms-WMI-intFlags4',
    'fb920c2c-f294-4426-8ac1-d24b42aa2bce': 'ms-WMI-intMax',
    '68c2e3ba-9837-4c70-98e0-f0c33695d023': 'ms-WMI-intMin',
    '6af565f6-a749-4b72-9634-3c5d47e6b4e0': 'ms-WMI-intValidValues',
    '6736809f-2064-443e-a145-81262b1f1366': 'ms-WMI-Mof',
    'c6c8ace5-7e81-42af-ad72-77412c5941c4': 'ms-WMI-Name',
    'eaba628f-eb8e-4fe9-83fc-693be695559b': 'ms-WMI-NormalizedClass',
    '27e81485-b1b0-4a8b-bedd-ce19a837e26e': 'ms-WMI-Parm1',
    '0003508e-9c42-4a76-a8f4-38bf64bab0de': 'ms-WMI-Parm2',
    '45958fb6-52bd-48ce-9f9f-c2712d9f2bfc': 'ms-WMI-Parm3',
    '3800d5a3-f1ce-4b82-a59a-1528ea795f59': 'ms-WMI-Parm4',
    'ab920883-e7f8-4d72-b4a0-c0449897509d': 'ms-WMI-PropertyName',
    '65fff93e-35e3-45a3-85ae-876c6718297f': 'ms-WMI-Query',
    '7d3cfa98-c17b-4254-8bd7-4de9b932a345': 'ms-WMI-QueryLanguage',
    '87b78d51-405f-4b7f-80ed-2bd28786f48d': 'ms-WMI-ScopeGuid',
    '34f7ed6c-615d-418d-aa00-549a7d7be03e': 'ms-WMI-SourceOrganization',
    '152e42b6-37c5-4f55-ab48-1606384a9aea': 'ms-WMI-stringDefault',
    '37609d31-a2bf-4b58-8f53-2b64e57a076d': 'ms-WMI-stringValidValues',
    '95b6d8d6-c9e8-4661-a2bc-6a5cabc04c62': 'ms-WMI-TargetClass',
    '1c4ab61f-3420-44e5-849d-8b5dbf60feb7': 'ms-WMI-TargetNameSpace',
    'c44f67a5-7de5-4a1f-92d9-662b57364b77': 'ms-WMI-TargetObject',
    '5006a79a-6bfe-4561-9f52-13cf4dd3e560': 'ms-WMI-TargetPath',
    'ca2a281e-262b-4ff7-b419-bc123352a4e9': 'ms-WMI-TargetType',
    '963d2751-48be-11d1-a9c3-0000f80367c1': 'Mscope-Id',
    '7bfdcb7d-4807-11d1-a9c3-0000f80367c1': 'Msi-File-List',
    'd9e18313-8939-11d1-aebc-0000f80367c1': 'Msi-Script',
    '96a7dd62-9118-11d1-aebc-0000f80367c1': 'Msi-Script-Name',
    'bf967937-0de6-11d0-a285-00aa003049e2': 'Msi-Script-Path',
    '96a7dd63-9118-11d1-aebc-0000f80367c1': 'Msi-Script-Size',
    '9a0dc326-c100-11d1-bbc5-0080c76670c0': 'MSMQ-Authenticate',
    '9a0dc323-c100-11d1-bbc5-0080c76670c0': 'MSMQ-Base-Priority',
    '9a0dc32e-c100-11d1-bbc5-0080c76670c0': 'MSMQ-Computer-Type',
    '18120de8-f4c4-4341-bd95-32eb5bcf7c80': 'MSMQ-Computer-Type-Ex',
    '9a0dc33a-c100-11d1-bbc5-0080c76670c0': 'MSMQ-Cost',
    '9a0dc334-c100-11d1-bbc5-0080c76670c0': 'MSMQ-CSP-Name',
    '2df90d83-009f-11d2-aa4c-00c04fd7d83a': 'MSMQ-Dependent-Client-Service',
    '2df90d76-009f-11d2-aa4c-00c04fd7d83a': 'MSMQ-Dependent-Client-Services',
    '9a0dc33c-c100-11d1-bbc5-0080c76670c0': 'MSMQ-Digests',
    '0f71d8e0-da3b-11d1-90a5-00c04fd91ab1': 'MSMQ-Digests-Mig',
    '2df90d82-009f-11d2-aa4c-00c04fd7d83a': 'MSMQ-Ds-Service',
    '2df90d78-009f-11d2-aa4c-00c04fd7d83a': 'MSMQ-Ds-Services',
    '9a0dc331-c100-11d1-bbc5-0080c76670c0': 'MSMQ-Encrypt-Key',
    '9a0dc32f-c100-11d1-bbc5-0080c76670c0': 'MSMQ-Foreign',
    '9a0dc32c-c100-11d1-bbc5-0080c76670c0': 'MSMQ-In-Routing-Servers',
    '8ea825aa-3b7b-11d2-90cc-00c04fd91ab1': 'MSMQ-Interval1',
    '99b88f52-3b7b-11d2-90cc-00c04fd91ab1': 'MSMQ-Interval2',
    '9a0dc321-c100-11d1-bbc5-0080c76670c0': 'MSMQ-Journal',
    '9a0dc324-c100-11d1-bbc5-0080c76670c0': 'MSMQ-Journal-Quota',
    '9a0dc325-c100-11d1-bbc5-0080c76670c0': 'MSMQ-Label',
    '4580ad25-d407-48d2-ad24-43e6e56793d7': 'MSMQ-Label-Ex',
    '9a0dc335-c100-11d1-bbc5-0080c76670c0': 'MSMQ-Long-Lived',
    '9a0dc33f-c100-11d1-bbc5-0080c76670c0': 'MSMQ-Migrated',
    '1d2f4412-f10d-4337-9b48-6e5b125cd265': 'MSMQ-Multicast-Address',
    '9a0dc333-c100-11d1-bbc5-0080c76670c0': 'MSMQ-Name-Style',
    'eb38a158-d57f-11d1-90a2-00c04fd91ab1': 'MSMQ-Nt4-Flags',
    '6f914be6-d57e-11d1-90a2-00c04fd91ab1': 'MSMQ-Nt4-Stub',
    '9a0dc330-c100-11d1-bbc5-0080c76670c0': 'MSMQ-OS-Type',
    '9a0dc32b-c100-11d1-bbc5-0080c76670c0': 'MSMQ-Out-Routing-Servers',
    '9a0dc328-c100-11d1-bbc5-0080c76670c0': 'MSMQ-Owner-ID',
    '2df90d75-009f-11d2-aa4c-00c04fd7d83a': 'MSMQ-Prev-Site-Gates',
    '9a0dc327-c100-11d1-bbc5-0080c76670c0': 'MSMQ-Privacy-Level',
    '9a0dc33e-c100-11d1-bbc5-0080c76670c0': 'MSMQ-QM-ID',
    '8e441266-d57f-11d1-90a2-00c04fd91ab1': 'MSMQ-Queue-Journal-Quota',
    '2df90d87-009f-11d2-aa4c-00c04fd7d83a': 'MSMQ-Queue-Name-Ext',
    '3f6b8e12-d57f-11d1-90a2-00c04fd91ab1': 'MSMQ-Queue-Quota',
    '9a0dc320-c100-11d1-bbc5-0080c76670c0': 'MSMQ-Queue-Type',
    '9a0dc322-c100-11d1-bbc5-0080c76670c0': 'MSMQ-Quota',
    '3bfe6748-b544-485a-b067-1b310c4334bf': 'MSMQ-Recipient-FormatName',
    '2df90d81-009f-11d2-aa4c-00c04fd7d83a': 'MSMQ-Routing-Service',
    '2df90d77-009f-11d2-aa4c-00c04fd7d83a': 'MSMQ-Routing-Services',
    '8bf0221b-7a06-4d63-91f0-1499941813d3': 'MSMQ-Secured-Source',
    '9a0dc32d-c100-11d1-bbc5-0080c76670c0': 'MSMQ-Service-Type',
    '9a0dc33d-c100-11d1-bbc5-0080c76670c0': 'MSMQ-Services',
    '9a0dc33b-c100-11d1-bbc5-0080c76670c0': 'MSMQ-Sign-Certificates',
    '3881b8ea-da3b-11d1-90a5-00c04fd91ab1': 'MSMQ-Sign-Certificates-Mig',
    '9a0dc332-c100-11d1-bbc5-0080c76670c0': 'MSMQ-Sign-Key',
    '9a0dc337-c100-11d1-bbc5-0080c76670c0': 'MSMQ-Site-1',
    '9a0dc338-c100-11d1-bbc5-0080c76670c0': 'MSMQ-Site-2',
    'fd129d8a-d57e-11d1-90a2-00c04fd91ab1': 'MSMQ-Site-Foreign',
    '9a0dc339-c100-11d1-bbc5-0080c76670c0': 'MSMQ-Site-Gates',
    'e2704852-3b7b-11d2-90cc-00c04fd91ab1': 'MSMQ-Site-Gates-Mig',
    '9a0dc340-c100-11d1-bbc5-0080c76670c0': 'MSMQ-Site-ID',
    'ffadb4b2-de39-11d1-90a5-00c04fd91ab1': 'MSMQ-Site-Name',
    '422144fa-c17f-4649-94d6-9731ed2784ed': 'MSMQ-Site-Name-Ex',
    '9a0dc32a-c100-11d1-bbc5-0080c76670c0': 'MSMQ-Sites',
    '9a0dc329-c100-11d1-bbc5-0080c76670c0': 'MSMQ-Transactional',
    'c58aae32-56f9-11d2-90d0-00c04fd91ab1': 'MSMQ-User-Sid',
    '9a0dc336-c100-11d1-bbc5-0080c76670c0': 'MSMQ-Version',
    'db0c9085-c1f2-11d1-bbc5-0080c76670c0': 'msNPAllowDialin',
    'db0c9089-c1f2-11d1-bbc5-0080c76670c0': 'msNPCalledStationID',
    'db0c908a-c1f2-11d1-bbc5-0080c76670c0': 'msNPCallingStationID',
    'db0c908e-c1f2-11d1-bbc5-0080c76670c0': 'msNPSavedCallingStationID',
    'db0c909c-c1f2-11d1-bbc5-0080c76670c0': 'msRADIUSCallbackNumber',
    'db0c90a4-c1f2-11d1-bbc5-0080c76670c0': 'msRADIUSFramedIPAddress',
    'db0c90a9-c1f2-11d1-bbc5-0080c76670c0': 'msRADIUSFramedRoute',
    'db0c90b6-c1f2-11d1-bbc5-0080c76670c0': 'msRADIUSServiceType',
    'db0c90c5-c1f2-11d1-bbc5-0080c76670c0': 'msRASSavedCallbackNumber',
    'db0c90c6-c1f2-11d1-bbc5-0080c76670c0': 'msRASSavedFramedIPAddress',
    'db0c90c7-c1f2-11d1-bbc5-0080c76670c0': 'msRASSavedFramedRoute',
    '20ebf171-c69a-4c31-b29d-dcb837d8912d': 'msSFU-30-Aliases',
    '4503d2a3-3d70-41b8-b077-dff123c15865': 'msSFU-30-Crypt-Method',
    '93095ed3-6f30-4bdd-b734-65d569f5f7c9': 'msSFU-30-Domains',
    'a2e11a42-e781-4ca1-a7fa-ec307f62b6a1': 'msSFU-30-Field-Separator',
    '95b2aef0-27e4-4cb9-880a-a2d9a9ea23b8': 'msSFU-30-Intra-Field-Separator',
    '0dea42f5-278d-4157-b4a7-49b59664915b': 'msSFU-30-Is-Valid-Container',
    '32ecd698-ce9e-4894-a134-7ad76b082e83': 'msSFU-30-Key-Attributes',
    '37830235-e5e9-46f2-922b-d8d44f03e7ae': 'msSFU-30-Key-Values',
    'b7b16e01-024f-4e23-ad0d-71f1a406b684': 'msSFU-30-Map-Filter',
    '4cc908a2-9e18-410e-8459-f17cc422020a': 'msSFU-30-Master-Server-Name',
    '04ee6aa6-f83b-469a-bf5a-3c00d3634669': 'msSFU-30-Max-Gid-Number',
    'ec998437-d944-4a28-8500-217588adfc75': 'msSFU-30-Max-Uid-Number',
    '16c5d1d3-35c2-4061-a870-a5cefda804f0': 'msSFU-30-Name',
    '97d2bf65-0466-4852-a25a-ec20f57ee36c': 'msSFU-30-Netgroup-Host-At-Domain',
    'a9e84eed-e630-4b67-b4b3-cad2a82d345e': 'msSFU-30-Netgroup-User-At-Domain',
    '9ee3b2e3-c7f3-45f8-8c9f-1382be4984d2': 'msSFU-30-Nis-Domain',
    '585c9d5e-f599-4f07-9cf9-4373af4b89d3': 'msSFU-30-NSMAP-Field-Position',
    '02625f05-d1ee-4f9f-b366-55266becb95c': 'msSFU-30-Order-Number',
    'c875d82d-2848-4cec-bb50-3c5486d09d57': 'msSFU-30-Posix-Member',
    '7bd76b92-3244-438a-ada6-24f5ea34381e': 'msSFU-30-Posix-Member-Of',
    'e167b0b6-4045-4433-ac35-53f972d45cba': 'msSFU-30-Result-Attributes',
    'ef9a2df0-2e57-48c8-8950-0cc674004733': 'msSFU-30-Search-Attributes',
    '27eebfa2-fbeb-4f8e-aad6-c50247994291': 'msSFU-30-Search-Container',
    '084a944b-e150-4bfe-9345-40e1aedaebba': 'msSFU-30-Yp-Servers',
    'bf9679d3-0de6-11d0-a285-00aa003049e2': 'Must-Contain',
    '80212840-4bdc-11d1-a9c4-0000f80367c1': 'Name-Service-Flags',
    'bf9679d6-0de6-11d0-a285-00aa003049e2': 'NC-Name',
    'bf9679d8-0de6-11d0-a285-00aa003049e2': 'NETBIOS-Name',
    '07383076-91df-11d1-aebc-0000f80367c1': 'netboot-Allow-New-Clients',
    '0738307b-91df-11d1-aebc-0000f80367c1': 'netboot-Answer-Only-Valid-Clients',
    '0738307a-91df-11d1-aebc-0000f80367c1': 'netboot-Answer-Requests',
    '07383079-91df-11d1-aebc-0000f80367c1': 'netboot-Current-Client-Count',
    '532570bd-3d77-424f-822f-0d636dc6daad': 'Netboot-DUID',
    '3e978921-8c01-11d0-afda-00c04fd930c9': 'Netboot-GUID',
    '3e978920-8c01-11d0-afda-00c04fd930c9': 'Netboot-Initialization',
    '0738307e-91df-11d1-aebc-0000f80367c1': 'netboot-IntelliMirror-OSes',
    '07383077-91df-11d1-aebc-0000f80367c1': 'netboot-Limit-Clients',
    '07383080-91df-11d1-aebc-0000f80367c1': 'netboot-Locally-Installed-OSes',
    '3e978923-8c01-11d0-afda-00c04fd930c9': 'Netboot-Machine-File-Path',
    '07383078-91df-11d1-aebc-0000f80367c1': 'netboot-Max-Clients',
    '2df90d85-009f-11d2-aa4c-00c04fd7d83a': 'Netboot-Mirror-Data-File',
    '0738307c-91df-11d1-aebc-0000f80367c1': 'netboot-New-Machine-Naming-Policy',
    '0738307d-91df-11d1-aebc-0000f80367c1': 'netboot-New-Machine-OU',
    '07383082-91df-11d1-aebc-0000f80367c1': 'netboot-SCP-BL',
    '07383081-91df-11d1-aebc-0000f80367c1': 'netboot-Server',
    '2df90d84-009f-11d2-aa4c-00c04fd7d83a': 'Netboot-SIF-File',
    '0738307f-91df-11d1-aebc-0000f80367c1': 'netboot-Tools',
    'bf9679d9-0de6-11d0-a285-00aa003049e2': 'Network-Address',
    'bf9679da-0de6-11d0-a285-00aa003049e2': 'Next-Level-Store',
    'bf9679db-0de6-11d0-a285-00aa003049e2': 'Next-Rid',
    '4a95216e-fcc0-402e-b57f-5971626148a9': 'NisMapEntry',
    '969d3c79-0e9a-4d95-b0ac-bdde7ff8f3a1': 'NisMapName',
    'a8032e74-30ef-4ff5-affc-0fc217783fec': 'NisNetgroupTriple',
    '52458018-ca6a-11d0-afff-0000f80367c1': 'Non-Security-Member',
    '52458019-ca6a-11d0-afff-0000f80367c1': 'Non-Security-Member-BL',
    '19195a56-6da0-11d0-afd3-00c04fd930c9': 'Notification-List',
    'bf9679df-0de6-11d0-a285-00aa003049e2': 'NT-Group-Members',
    '3e97891f-8c01-11d0-afda-00c04fd930c9': 'NT-Mixed-Domain',
    'bf9679e2-0de6-11d0-a285-00aa003049e2': 'Nt-Pwd-History',
    'bf9679e3-0de6-11d0-a285-00aa003049e2': 'NT-Security-Descriptor',
    'bf9679e4-0de6-11d0-a285-00aa003049e2': 'Obj-Dist-Name',
    '26d97369-6070-11d1-a9c6-0000f80367c1': 'Object-Category',
    'bf9679e5-0de6-11d0-a285-00aa003049e2': 'Object-Class',
    'bf9679e6-0de6-11d0-a285-00aa003049e2': 'Object-Class-Category',
    '9a7ad94b-ca53-11d1-bbd0-0080c76670c0': 'Object-Classes',
    '34aaa216-b699-11d0-afee-0000f80367c1': 'Object-Count',
    'bf9679e7-0de6-11d0-a285-00aa003049e2': 'Object-Guid',
    'bf9679e8-0de6-11d0-a285-00aa003049e2': 'Object-Sid',
    '16775848-47f3-11d1-a9c3-0000f80367c1': 'Object-Version',
    'bf9679ea-0de6-11d0-a285-00aa003049e2': 'OEM-Information',
    'bf9679ec-0de6-11d0-a285-00aa003049e2': 'OM-Object-Class',
    'bf9679ed-0de6-11d0-a285-00aa003049e2': 'OM-Syntax',
    'ddac0cf3-af8f-11d0-afeb-00c04fd930c9': 'OMT-Guid',
    '1f0075fa-7e40-11d0-afd6-00c04fd930c9': 'OMT-Indx-Guid',
    '966825f5-01d9-4a5c-a011-d15ae84efa55': 'OncRpcNumber',
    '3e978925-8c01-11d0-afda-00c04fd930c9': 'Operating-System',
    'bd951b3c-9c96-11d0-afdd-00c04fd930c9': 'Operating-System-Hotfix',
    '3e978927-8c01-11d0-afda-00c04fd930c9': 'Operating-System-Service-Pack',
    '3e978926-8c01-11d0-afda-00c04fd930c9': 'Operating-System-Version',
    'bf9679ee-0de6-11d0-a285-00aa003049e2': 'Operator-Count',
    '963d274d-48be-11d1-a9c3-0000f80367c1': 'Option-Description',
    '19195a53-6da0-11d0-afd3-00c04fd930c9': 'Options',
    '963d274e-48be-11d1-a9c3-0000f80367c1': 'Options-Location',
    'bf9679ef-0de6-11d0-a285-00aa003049e2': 'Organization-Name',
    'bf9679f0-0de6-11d0-a285-00aa003049e2': 'Organizational-Unit-Name',
    '28596019-7349-4d2f-adff-5a629961f942': 'organizationalStatus',
    '5fd424ce-1262-11d0-a060-00aa006c33ed': 'Original-Display-Table',
    '5fd424cf-1262-11d0-a060-00aa006c33ed': 'Original-Display-Table-MSDOS',
    'bf9679f1-0de6-11d0-a285-00aa003049e2': 'Other-Login-Workstations',
    '0296c123-40da-11d1-a9c0-0000f80367c1': 'Other-Mailbox',
    'bf9679f2-0de6-11d0-a285-00aa003049e2': 'Other-Name',
    '1ea64e5d-ac0f-11d2-90df-00c04fd91ab1': 'Other-Well-Known-Objects',
    'bf9679f3-0de6-11d0-a285-00aa003049e2': 'Owner',
    '7d6c0e99-7e20-11d0-afd6-00c04fd930c9': 'Package-Flags',
    '7d6c0e98-7e20-11d0-afd6-00c04fd930c9': 'Package-Name',
    '7d6c0e96-7e20-11d0-afd6-00c04fd930c9': 'Package-Type',
    '5245801b-ca6a-11d0-afff-0000f80367c1': 'Parent-CA',
    '963d2733-48be-11d1-a9c3-0000f80367c1': 'Parent-CA-Certificate-Chain',
    '2df90d74-009f-11d2-aa4c-00c04fd7d83a': 'Parent-GUID',
    '28630ec0-41d5-11d1-a9c1-0000f80367c1': 'Partial-Attribute-Deletion-List',
    '19405b9e-3cfa-11d1-a9c0-0000f80367c1': 'Partial-Attribute-Set',
    '07383084-91df-11d1-aebc-0000f80367c1': 'Pek-Key-Change-Interval',
    '07383083-91df-11d1-aebc-0000f80367c1': 'Pek-List',
    '963d273c-48be-11d1-a9c3-0000f80367c1': 'Pending-CA-Certificates',
    '963d273e-48be-11d1-a9c3-0000f80367c1': 'Pending-Parent-CA',
    '5fd424d3-1262-11d0-a060-00aa006c33ed': 'Per-Msg-Dialog-Display-Table',
    '5fd424d4-1262-11d0-a060-00aa006c33ed': 'Per-Recip-Dialog-Display-Table',
    '16775858-47f3-11d1-a9c3-0000f80367c1': 'Personal-Title',
    '0296c11d-40da-11d1-a9c0-0000f80367c1': 'Phone-Fax-Other',
    'f0f8ffa2-1191-11d0-a060-00aa006c33ed': 'Phone-Home-Other',
    'f0f8ffa1-1191-11d0-a060-00aa006c33ed': 'Phone-Home-Primary',
    '4d146e4b-48d4-11d1-a9c3-0000f80367c1': 'Phone-Ip-Other',
    '4d146e4a-48d4-11d1-a9c3-0000f80367c1': 'Phone-Ip-Primary',
    '0296c11f-40da-11d1-a9c0-0000f80367c1': 'Phone-ISDN-Primary',
    '0296c11e-40da-11d1-a9c0-0000f80367c1': 'Phone-Mobile-Other',
    'f0f8ffa3-1191-11d0-a060-00aa006c33ed': 'Phone-Mobile-Primary',
    'f0f8ffa5-1191-11d0-a060-00aa006c33ed': 'Phone-Office-Other',
    'f0f8ffa4-1191-11d0-a060-00aa006c33ed': 'Phone-Pager-Other',
    'f0f8ffa6-1191-11d0-a060-00aa006c33ed': 'Phone-Pager-Primary',
    '9c979768-ba1a-4c08-9632-c6a5c1ed649a': 'photo',
    'bf9679f7-0de6-11d0-a285-00aa003049e2': 'Physical-Delivery-Office-Name',
    'b7b13119-b82e-11d0-afee-0000f80367c1': 'Physical-Location-Object',
    '8d3bca50-1d7e-11d0-a081-00aa006c33ed': 'Picture',
    'fc5a9106-3b9d-11d2-90cc-00c04fd91ab1': 'PKI-Critical-Extensions',
    '1ef6336e-3b9e-11d2-90cc-00c04fd91ab1': 'PKI-Default-CSPs',
    '426cae6e-3b9d-11d2-90cc-00c04fd91ab1': 'PKI-Default-Key-Spec',
    '926be278-56f9-11d2-90d0-00c04fd91ab1': 'PKI-Enrollment-Access',
    '041570d2-3b9e-11d2-90cc-00c04fd91ab1': 'PKI-Expiration-Period',
    '18976af6-3b9e-11d2-90cc-00c04fd91ab1': 'PKI-Extended-Key-Usage',
    'e9b0a87e-3b9d-11d2-90cc-00c04fd91ab1': 'PKI-Key-Usage',
    'f0bfdefa-3b9d-11d2-90cc-00c04fd91ab1': 'PKI-Max-Issuing-Depth',
    '1219a3ec-3b9e-11d2-90cc-00c04fd91ab1': 'PKI-Overlap-Period',
    '8447f9f1-1027-11d0-a05f-00aa006c33ed': 'PKT',
    '8447f9f0-1027-11d0-a05f-00aa006c33ed': 'PKT-Guid',
    '19405b96-3cfa-11d1-a9c0-0000f80367c1': 'Policy-Replication-Flags',
    '281416c4-1968-11d0-a28f-00aa003049e2': 'Port-Name',
    'bf9679fa-0de6-11d0-a285-00aa003049e2': 'Poss-Superiors',
    '9a7ad94c-ca53-11d1-bbd0-0080c76670c0': 'Possible-Inferiors',
    'bf9679fb-0de6-11d0-a285-00aa003049e2': 'Post-Office-Box',
    'bf9679fc-0de6-11d0-a285-00aa003049e2': 'Postal-Address',
    'bf9679fd-0de6-11d0-a285-00aa003049e2': 'Postal-Code',
    'bf9679fe-0de6-11d0-a285-00aa003049e2': 'Preferred-Delivery-Method',
    'bf9679ff-0de6-11d0-a285-00aa003049e2': 'Preferred-OU',
    '856be0d0-18e7-46e1-8f5f-7ee4d9020e0d': 'preferredLanguage',
    '52458022-ca6a-11d0-afff-0000f80367c1': 'Prefix-Map',
    'a8df744b-c5ea-11d1-bbcb-0080c76670c0': 'Presentation-Address',
    '963d2739-48be-11d1-a9c3-0000f80367c1': 'Previous-CA-Certificates',
    '963d273d-48be-11d1-a9c3-0000f80367c1': 'Previous-Parent-CA',
    'bf967a00-0de6-11d0-a285-00aa003049e2': 'Primary-Group-ID',
    'c0ed8738-7efd-4481-84d9-66d2db8be369': 'Primary-Group-Token',
    '281416d7-1968-11d0-a28f-00aa003049e2': 'Print-Attributes',
    '281416cd-1968-11d0-a28f-00aa003049e2': 'Print-Bin-Names',
    '281416d2-1968-11d0-a28f-00aa003049e2': 'Print-Collate',
    '281416d3-1968-11d0-a28f-00aa003049e2': 'Print-Color',
    '281416cc-1968-11d0-a28f-00aa003049e2': 'Print-Duplex-Supported',
    '281416ca-1968-11d0-a28f-00aa003049e2': 'Print-End-Time',
    '281416cb-1968-11d0-a28f-00aa003049e2': 'Print-Form-Name',
    'ba305f6d-47e3-11d0-a1a6-00c04fd930c9': 'Print-Keep-Printed-Jobs',
    '281416d6-1968-11d0-a28f-00aa003049e2': 'Print-Language',
    'ba305f7a-47e3-11d0-a1a6-00c04fd930c9': 'Print-MAC-Address',
    '281416d1-1968-11d0-a28f-00aa003049e2': 'Print-Max-Copies',
    '281416cf-1968-11d0-a28f-00aa003049e2': 'Print-Max-Resolution-Supported',
    'ba305f6f-47e3-11d0-a1a6-00c04fd930c9': 'Print-Max-X-Extent',
    'ba305f70-47e3-11d0-a1a6-00c04fd930c9': 'Print-Max-Y-Extent',
    '3bcbfcf5-4d3d-11d0-a1a6-00c04fd930c9': 'Print-Media-Ready',
    '244b296f-5abd-11d0-afd2-00c04fd930c9': 'Print-Media-Supported',
    'ba305f74-47e3-11d0-a1a6-00c04fd930c9': 'Print-Memory',
    'ba305f71-47e3-11d0-a1a6-00c04fd930c9': 'Print-Min-X-Extent',
    'ba305f72-47e3-11d0-a1a6-00c04fd930c9': 'Print-Min-Y-Extent',
    'ba305f79-47e3-11d0-a1a6-00c04fd930c9': 'Print-Network-Address',
    'ba305f6a-47e3-11d0-a1a6-00c04fd930c9': 'Print-Notify',
    '3bcbfcf4-4d3d-11d0-a1a6-00c04fd930c9': 'Print-Number-Up',
    '281416d0-1968-11d0-a28f-00aa003049e2': 'Print-Orientations-Supported',
    'ba305f69-47e3-11d0-a1a6-00c04fd930c9': 'Print-Owner',
    '19405b97-3cfa-11d1-a9c0-0000f80367c1': 'Print-Pages-Per-Minute',
    'ba305f77-47e3-11d0-a1a6-00c04fd930c9': 'Print-Rate',
    'ba305f78-47e3-11d0-a1a6-00c04fd930c9': 'Print-Rate-Unit',
    '281416c6-1968-11d0-a28f-00aa003049e2': 'Print-Separator-File',
    'ba305f68-47e3-11d0-a1a6-00c04fd930c9': 'Print-Share-Name',
    'ba305f6c-47e3-11d0-a1a6-00c04fd930c9': 'Print-Spooling',
    'ba305f73-47e3-11d0-a1a6-00c04fd930c9': 'Print-Stapling-Supported',
    '281416c9-1968-11d0-a28f-00aa003049e2': 'Print-Start-Time',
    'ba305f6b-47e3-11d0-a1a6-00c04fd930c9': 'Print-Status',
    '244b296e-5abd-11d0-afd2-00c04fd930c9': 'Printer-Name',
    'bf967a01-0de6-11d0-a285-00aa003049e2': 'Prior-Set-Time',
    'bf967a02-0de6-11d0-a285-00aa003049e2': 'Prior-Value',
    '281416c7-1968-11d0-a28f-00aa003049e2': 'Priority',
    'bf967a03-0de6-11d0-a285-00aa003049e2': 'Private-Key',
    '19405b9a-3cfa-11d1-a9c0-0000f80367c1': 'Privilege-Attributes',
    '19405b98-3cfa-11d1-a9c0-0000f80367c1': 'Privilege-Display-Name',
    '19405b9b-3cfa-11d1-a9c0-0000f80367c1': 'Privilege-Holder',
    '19405b99-3cfa-11d1-a9c0-0000f80367c1': 'Privilege-Value',
    'd9e18317-8939-11d1-aebc-0000f80367c1': 'Product-Code',
    'bf967a05-0de6-11d0-a285-00aa003049e2': 'Profile-Path',
    'e1aea402-cd5b-11d0-afff-0000f80367c1': 'Proxied-Object-Name',
    'bf967a06-0de6-11d0-a285-00aa003049e2': 'Proxy-Addresses',
    '5fd424d6-1262-11d0-a060-00aa006c33ed': 'Proxy-Generation-Enabled',
    'bf967a07-0de6-11d0-a285-00aa003049e2': 'Proxy-Lifetime',
    '80a67e28-9f22-11d0-afdd-00c04fd930c9': 'Public-Key-Policy',
    'b4b54e50-943a-11d1-aebd-0000f80367c1': 'Purported-Search',
    'bf967a09-0de6-11d0-a285-00aa003049e2': 'Pwd-History-Length',
    'bf967a0a-0de6-11d0-a285-00aa003049e2': 'Pwd-Last-Set',
    'bf967a0b-0de6-11d0-a285-00aa003049e2': 'Pwd-Properties',
    '80a67e4e-9f22-11d0-afdd-00c04fd930c9': 'Quality-Of-Service',
    'cbf70a26-7e78-11d2-9921-0000f87a57d4': 'Query-Filter',
    'e1aea404-cd5b-11d0-afff-0000f80367c1': 'Query-Policy-BL',
    'e1aea403-cd5b-11d0-afff-0000f80367c1': 'Query-Policy-Object',
    '7bfdcb86-4807-11d1-a9c3-0000f80367c1': 'QueryPoint',
    'bf967a0c-0de6-11d0-a285-00aa003049e2': 'Range-Lower',
    'bf967a0d-0de6-11d0-a285-00aa003049e2': 'Range-Upper',
    'bf967a0e-0de6-11d0-a285-00aa003049e2': 'RDN',
    'bf967a0f-0de6-11d0-a285-00aa003049e2': 'RDN-Att-ID',
    'bf967a10-0de6-11d0-a285-00aa003049e2': 'Registered-Address',
    'bf967a12-0de6-11d0-a285-00aa003049e2': 'Remote-Server-Name',
    'bf967a14-0de6-11d0-a285-00aa003049e2': 'Remote-Source',
    'bf967a15-0de6-11d0-a285-00aa003049e2': 'Remote-Source-Type',
    '2a39c5b0-8960-11d1-aebc-0000f80367c1': 'Remote-Storage-GUID',
    '45ba9d1a-56fa-11d2-90d0-00c04fd91ab1': 'Repl-Interval',
    '281416c0-1968-11d0-a28f-00aa003049e2': 'Repl-Property-Meta-Data',
    '7bfdcb83-4807-11d1-a9c3-0000f80367c1': 'Repl-Topology-Stay-Of-Execution',
    'bf967a16-0de6-11d0-a285-00aa003049e2': 'Repl-UpToDate-Vector',
    'bf967a18-0de6-11d0-a285-00aa003049e2': 'Replica-Source',
    'bf967a1c-0de6-11d0-a285-00aa003049e2': 'Reports',
    'bf967a1d-0de6-11d0-a285-00aa003049e2': 'Reps-From',
    'bf967a1e-0de6-11d0-a285-00aa003049e2': 'Reps-To',
    '7d6c0e93-7e20-11d0-afd6-00c04fd930c9': 'Required-Categories',
    '7bfdcb7f-4807-11d1-a9c3-0000f80367c1': 'Retired-Repl-DSA-Signatures',
    'bf967a21-0de6-11d0-a285-00aa003049e2': 'Revision',
    'bf967a22-0de6-11d0-a285-00aa003049e2': 'Rid',
    '66171889-8f3c-11d0-afda-00c04fd930c9': 'RID-Allocation-Pool',
    '66171888-8f3c-11d0-afda-00c04fd930c9': 'RID-Available-Pool',
    '66171886-8f3c-11d0-afda-00c04fd930c9': 'RID-Manager-Reference',
    '6617188c-8f3c-11d0-afda-00c04fd930c9': 'RID-Next-RID',
    '6617188a-8f3c-11d0-afda-00c04fd930c9': 'RID-Previous-Allocation-Pool',
    '7bfdcb7b-4807-11d1-a9c3-0000f80367c1': 'RID-Set-References',
    '6617188b-8f3c-11d0-afda-00c04fd930c9': 'RID-Used-Pool',
    '8297931c-86d3-11d0-afda-00c04fd930c9': 'Rights-Guid',
    'a8df7465-c5ea-11d1-bbcb-0080c76670c0': 'Role-Occupant',
    '81d7f8c2-e327-4a0d-91c6-b42d4009115f': 'roomNumber',
    '7bfdcb80-4807-11d1-a9c3-0000f80367c1': 'Root-Trust',
    '88611bde-8cf4-11d0-afda-00c04fd930c9': 'rpc-Ns-Annotation',
    'bf967a23-0de6-11d0-a285-00aa003049e2': 'rpc-Ns-Bindings',
    '7a0ba0e0-8e98-11d0-afda-00c04fd930c9': 'rpc-Ns-Codeset',
    '80212841-4bdc-11d1-a9c4-0000f80367c1': 'rpc-Ns-Entry-Flags',
    'bf967a24-0de6-11d0-a285-00aa003049e2': 'rpc-Ns-Group',
    'bf967a25-0de6-11d0-a285-00aa003049e2': 'rpc-Ns-Interface-ID',
    '29401c48-7a27-11d0-afd6-00c04fd930c9': 'rpc-Ns-Object-ID',
    'bf967a27-0de6-11d0-a285-00aa003049e2': 'rpc-Ns-Priority',
    'bf967a28-0de6-11d0-a285-00aa003049e2': 'rpc-Ns-Profile-Entry',
    '29401c4a-7a27-11d0-afd6-00c04fd930c9': 'rpc-Ns-Transfer-Syntax',
    '3e0abfd0-126a-11d0-a060-00aa006c33ed': 'SAM-Account-Name',
    '6e7b626c-64f2-11d0-afd2-00c04fd930c9': 'SAM-Account-Type',
    '04d2d114-f799-4e9b-bcdc-90e8f5ba7ebe': 'SAM-Domain-Updates',
    'dd712224-10e4-11d0-a05f-00aa006c33ed': 'Schedule',
    'bf967a2b-0de6-11d0-a285-00aa003049e2': 'Schema-Flags-Ex',
    'bf967923-0de6-11d0-a285-00aa003049e2': 'Schema-ID-GUID',
    'f9fb64ae-93b4-11d2-9945-0000f87a57d4': 'Schema-Info',
    '1e2d06b4-ac8f-11d0-afe3-00c04fd930c9': 'Schema-Update',
    'bf967a2c-0de6-11d0-a285-00aa003049e2': 'Schema-Version',
    '16f3a4c2-7e79-11d2-9921-0000f87a57d4': 'Scope-Flags',
    'bf9679a8-0de6-11d0-a285-00aa003049e2': 'Script-Path',
    'c3dbafa6-33df-11d2-98b2-0000f87a57d4': 'SD-Rights-Effective',
    'bf967a2d-0de6-11d0-a285-00aa003049e2': 'Search-Flags',
    'bf967a2e-0de6-11d0-a285-00aa003049e2': 'Search-Guide',
    '01072d9a-98ad-4a53-9744-e83e287278fb': 'secretary',
    'bf967a2f-0de6-11d0-a285-00aa003049e2': 'Security-Identifier',
    'bf967a31-0de6-11d0-a285-00aa003049e2': 'See-Also',
    'ddac0cf2-af8f-11d0-afeb-00c04fd930c9': 'Seq-Notification',
    'bf967a32-0de6-11d0-a285-00aa003049e2': 'Serial-Number',
    '09dcb7a0-165f-11d0-a064-00aa006c33ed': 'Server-Name',
    '26d9736d-6070-11d1-a9c6-0000f80367c1': 'Server-Reference',
    '26d9736e-6070-11d1-a9c6-0000f80367c1': 'Server-Reference-BL',
    'bf967a33-0de6-11d0-a285-00aa003049e2': 'Server-Role',
    'bf967a34-0de6-11d0-a285-00aa003049e2': 'Server-State',
    'b7b1311c-b82e-11d0-afee-0000f80367c1': 'Service-Binding-Information',
    'bf967a35-0de6-11d0-a285-00aa003049e2': 'Service-Class-ID',
    'bf967a36-0de6-11d0-a285-00aa003049e2': 'Service-Class-Info',
    'b7b1311d-b82e-11d0-afee-0000f80367c1': 'Service-Class-Name',
    '28630eb8-41d5-11d1-a9c1-0000f80367c1': 'Service-DNS-Name',
    '28630eba-41d5-11d1-a9c1-0000f80367c1': 'Service-DNS-Name-Type',
    'bf967a37-0de6-11d0-a285-00aa003049e2': 'Service-Instance-Version',
    'f3a64788-5306-11d1-a9c5-0000f80367c1': 'Service-Principal-Name',
    '7d6c0e97-7e20-11d0-afd6-00c04fd930c9': 'Setup-Command',
    '75159a00-1fff-4cf4-8bff-4ef2695cf643': 'ShadowExpire',
    '8dfeb70d-c5db-46b6-b15e-a4389e6cee9b': 'ShadowFlag',
    '86871d1f-3310-4312-8efd-af49dcfb2671': 'ShadowInactive',
    'f8f2689c-29e8-4843-8177-e8b98e15eeac': 'ShadowLastChange',
    'f285c952-50dd-449e-9160-3b880d99988d': 'ShadowMax',
    'a76b8737-e5a1-4568-b057-dc12e04be4b2': 'ShadowMin',
    '7ae89c9c-2976-4a46-bb8a-340f88560117': 'ShadowWarning',
    '553fd039-f32e-11d0-b0bc-00c04fd8dca6': 'Shell-Context-Menu',
    '52458039-ca6a-11d0-afff-0000f80367c1': 'Shell-Property-Pages',
    '45b01501-c419-11d1-bbc9-0080c76670c0': 'Short-Server-Name',
    '3e74f60e-3e73-11d1-a9c0-0000f80367c1': 'Show-In-Address-Book',
    'bf967984-0de6-11d0-a285-00aa003049e2': 'Show-In-Advanced-View-Only',
    '17eb4278-d167-11d0-b002-0000f80367c1': 'SID-History',
    '2a39c5b2-8960-11d1-aebc-0000f80367c1': 'Signature-Algorithms',
    '3e978924-8c01-11d0-afda-00c04fd930c9': 'Site-GUID',
    'd50c2cdd-8951-11d1-aebc-0000f80367c1': 'Site-Link-List',
    'd50c2cdc-8951-11d1-aebc-0000f80367c1': 'Site-List',
    '3e10944c-c354-11d0-aff8-0000f80367c1': 'Site-Object',
    '3e10944d-c354-11d0-aff8-0000f80367c1': 'Site-Object-BL',
    '1be8f17c-a9ff-11d0-afe2-00c04fd930c9': 'Site-Server',
    '26d9736f-6070-11d1-a9c6-0000f80367c1': 'SMTP-Mail-Address',
    '2ab0e76c-7041-11d2-9905-0000f87a57d4': 'SPN-Mappings',
    'bf967a39-0de6-11d0-a285-00aa003049e2': 'State-Or-Province-Name',
    'bf967a3a-0de6-11d0-a285-00aa003049e2': 'Street-Address',
    '3860949f-f6a8-4b38-9950-81ecb6bc2982': 'Structural-Object-Class',
    'bf967a3b-0de6-11d0-a285-00aa003049e2': 'Sub-Class-Of',
    'bf967a3c-0de6-11d0-a285-00aa003049e2': 'Sub-Refs',
    '9a7ad94d-ca53-11d1-bbd0-0080c76670c0': 'SubSchemaSubEntry',
    '963d274c-48be-11d1-a9c3-0000f80367c1': 'Super-Scope-Description',
    '963d274b-48be-11d1-a9c3-0000f80367c1': 'Super-Scopes',
    '5245801d-ca6a-11d0-afff-0000f80367c1': 'Superior-DNS-Root',
    'bf967a3f-0de6-11d0-a285-00aa003049e2': 'Supplemental-Credentials',
    '1677588f-47f3-11d1-a9c3-0000f80367c1': 'Supported-Application-Context',
    'bf967a41-0de6-11d0-a285-00aa003049e2': 'Surname',
    '037651e4-441d-11d1-a9c3-0000f80367c1': 'Sync-Attributes',
    '037651e3-441d-11d1-a9c3-0000f80367c1': 'Sync-Membership',
    '037651e2-441d-11d1-a9c3-0000f80367c1': 'Sync-With-Object',
    '037651e5-441d-11d1-a9c3-0000f80367c1': 'Sync-With-SID',
    'bf967a43-0de6-11d0-a285-00aa003049e2': 'System-Auxiliary-Class',
    'e0fa1e62-9b45-11d0-afdd-00c04fd930c9': 'System-Flags',
    'bf967a44-0de6-11d0-a285-00aa003049e2': 'System-May-Contain',
    'bf967a45-0de6-11d0-a285-00aa003049e2': 'System-Must-Contain',
    'bf967a46-0de6-11d0-a285-00aa003049e2': 'System-Only',
    'bf967a47-0de6-11d0-a285-00aa003049e2': 'System-Poss-Superiors',
    'bf967a49-0de6-11d0-a285-00aa003049e2': 'Telephone-Number',
    'bf967a4a-0de6-11d0-a285-00aa003049e2': 'Teletex-Terminal-Identifier',
    'bf967a4b-0de6-11d0-a285-00aa003049e2': 'Telex-Number',
    '0296c121-40da-11d1-a9c0-0000f80367c1': 'Telex-Primary',
    'ed9de9a0-7041-11d2-9905-0000f87a57d4': 'Template-Roots',
    'b1cba91a-0682-4362-a659-153e201ef069': 'Template-Roots2',
    '6db69a1c-9422-11d1-aebd-0000f80367c1': 'Terminal-Server',
    'f0f8ffa7-1191-11d0-a060-00aa006c33ed': 'Text-Country',
    'a8df7489-c5ea-11d1-bbcb-0080c76670c0': 'Text-Encoded-OR-Address',
    'ddac0cf1-af8f-11d0-afeb-00c04fd930c9': 'Time-Refresh',
    'ddac0cf0-af8f-11d0-afeb-00c04fd930c9': 'Time-Vol-Change',
    'bf967a55-0de6-11d0-a285-00aa003049e2': 'Title',
    'b7c69e6d-2cc7-11d2-854e-00a0c983f608': 'Token-Groups',
    '46a9b11d-60ae-405a-b7e8-ff8a58d456d2': 'Token-Groups-Global-And-Universal',
    '040fc392-33df-11d2-98b2-0000f87a57d4': 'Token-Groups-No-GC-Acceptable',
    '16c3a860-1273-11d0-a060-00aa006c33ed': 'Tombstone-Lifetime',
    'c1dc867c-a261-11d1-b606-0000f80367c1': 'Transport-Address-Attribute',
    '26d97372-6070-11d1-a9c6-0000f80367c1': 'Transport-DLL-Name',
    '26d97374-6070-11d1-a9c6-0000f80367c1': 'Transport-Type',
    '8fd044e3-771f-11d1-aeae-0000f80367c1': 'Treat-As-Leaf',
    '28630ebd-41d5-11d1-a9c1-0000f80367c1': 'Tree-Name',
    '80a67e5a-9f22-11d0-afdd-00c04fd930c9': 'Trust-Attributes',
    'bf967a59-0de6-11d0-a285-00aa003049e2': 'Trust-Auth-Incoming',
    'bf967a5f-0de6-11d0-a285-00aa003049e2': 'Trust-Auth-Outgoing',
    'bf967a5c-0de6-11d0-a285-00aa003049e2': 'Trust-Direction',
    'b000ea7a-a086-11d0-afdd-00c04fd930c9': 'Trust-Parent',
    'bf967a5d-0de6-11d0-a285-00aa003049e2': 'Trust-Partner',
    'bf967a5e-0de6-11d0-a285-00aa003049e2': 'Trust-Posix-Offset',
    'bf967a60-0de6-11d0-a285-00aa003049e2': 'Trust-Type',
    'bf967a61-0de6-11d0-a285-00aa003049e2': 'UAS-Compat',
    '0bb0fca0-1e89-429f-901a-1413894d9f59': 'uid',
    '850fcc8f-9c6b-47e1-b671-7c654be4d5b3': 'UidNumber',
    'bf967a64-0de6-11d0-a285-00aa003049e2': 'UNC-Name',
    'bf9679e1-0de6-11d0-a285-00aa003049e2': 'Unicode-Pwd',
    'ba0184c7-38c5-4bed-a526-75421470580c': 'uniqueIdentifier',
    '8f888726-f80a-44d7-b1ee-cb9df21392c8': 'uniqueMember',
    'bc2dba12-000f-464d-bf1d-0808465d8843': 'UnixHomeDirectory',
    '612cb747-c0e8-4f92-9221-fdd5f15b550d': 'UnixUserPassword',
    '50950839-cc4c-4491-863a-fcf942d684b7': 'unstructuredAddress',
    '9c8ef177-41cf-45c9-9673-7716c0c8901b': 'unstructuredName',
    'd9e18312-8939-11d1-aebc-0000f80367c1': 'Upgrade-Product-Code',
    '032160bf-9824-11d1-aec0-0000f80367c1': 'UPN-Suffixes',
    'bf967a68-0de6-11d0-a285-00aa003049e2': 'User-Account-Control',
    'bf967a69-0de6-11d0-a285-00aa003049e2': 'User-Cert',
    'bf967a6a-0de6-11d0-a285-00aa003049e2': 'User-Comment',
    'bf967a6d-0de6-11d0-a285-00aa003049e2': 'User-Parameters',
    'bf967a6e-0de6-11d0-a285-00aa003049e2': 'User-Password',
    '28630ebb-41d5-11d1-a9c1-0000f80367c1': 'User-Principal-Name',
    '9a9a021f-4a5b-11d1-a9c3-0000f80367c1': 'User-Shared-Folder',
    '9a9a0220-4a5b-11d1-a9c3-0000f80367c1': 'User-Shared-Folder-Other',
    'e16a9db2-403c-11d1-a9c0-0000f80367c1': 'User-SMIME-Certificate',
    'bf9679d7-0de6-11d0-a285-00aa003049e2': 'User-Workstations',
    '11732a8a-e14d-4cc5-b92f-d93f51c6d8e4': 'userClass',
    '23998ab5-70f8-4007-a4c1-a84a38311f9a': 'userPKCS12',
    'bf967a6f-0de6-11d0-a285-00aa003049e2': 'USN-Changed',
    'bf967a70-0de6-11d0-a285-00aa003049e2': 'USN-Created',
    'bf967a71-0de6-11d0-a285-00aa003049e2': 'USN-DSA-Last-Obj-Removed',
    'a8df7498-c5ea-11d1-bbcb-0080c76670c0': 'USN-Intersite',
    'bf967a73-0de6-11d0-a285-00aa003049e2': 'USN-Last-Obj-Rem',
    '167758ad-47f3-11d1-a9c3-0000f80367c1': 'USN-Source',
    '4d2fa380-7f54-11d2-992a-0000f87a57d4': 'Valid-Accesses',
    '281416df-1968-11d0-a28f-00aa003049e2': 'Vendor',
    'bf967a76-0de6-11d0-a285-00aa003049e2': 'Version-Number',
    '7d6c0e9a-7e20-11d0-afd6-00c04fd930c9': 'Version-Number-Hi',
    '7d6c0e9b-7e20-11d0-afd6-00c04fd930c9': 'Version-Number-Lo',
    '1f0075fd-7e40-11d0-afd6-00c04fd930c9': 'Vol-Table-GUID',
    '1f0075fb-7e40-11d0-afd6-00c04fd930c9': 'Vol-Table-Idx-GUID',
    '34aaa217-b699-11d0-afee-0000f80367c1': 'Volume-Count',
    '244b2970-5abd-11d0-afd2-00c04fd930c9': 'Wbem-Path',
    '05308983-7688-11d1-aded-00c04fd8d5cd': 'Well-Known-Objects',
    'bf967a77-0de6-11d0-a285-00aa003049e2': 'When-Changed',
    'bf967a78-0de6-11d0-a285-00aa003049e2': 'When-Created',
    'bf967a79-0de6-11d0-a285-00aa003049e2': 'Winsock-Addresses',
    'bf967a7a-0de6-11d0-a285-00aa003049e2': 'WWW-Home-Page',
    '9a9a0221-4a5b-11d1-a9c3-0000f80367c1': 'WWW-Page-Other',
    'bf967a7b-0de6-11d0-a285-00aa003049e2': 'X121-Address',
    'd07da11f-8a3d-42b6-b0aa-76c962be719a': 'x500uniqueIdentifier',
    'bf967a7f-0de6-11d0-a285-00aa003049e2': 'X509-Cert',
}

# GUID from https://docs.microsoft.com/en-us/windows/win32/adschema/classes-all
# https://docs.microsoft.com/ru-ru/openspecs/windows_protocols/ms-adsc/9abb5e97-123d-4da9-9557-b353ab79b830
CLASSES_BY_GUID: Dict[str, str] = {
    '2628a46a-a6ad-4ae0-b854-2b12d9fe6f9e': 'account',
    '7f561288-5301-11d1-a9c5-0000f80367c1': 'ACS-Policy',
    '2e899b04-2834-11d3-91d4-0000f87a57d4': 'ACS-Resource-Limits',
    '7f561289-5301-11d1-a9c5-0000f80367c1': 'ACS-Subnet',
    '3e74f60f-3e73-11d1-a9c0-0000f80367c1': 'Address-Book-Container',
    '5fd4250a-1262-11d0-a060-00aa006c33ed': 'Address-Template',
    '3fdfee4f-47f4-11d1-a9c3-0000f80367c1': 'Application-Entity',
    '5fd4250b-1262-11d0-a060-00aa006c33ed': 'Application-Process',
    'f780acc1-56f0-11d1-a9c6-0000f80367c1': 'Application-Settings',
    '19195a5c-6da0-11d0-afd3-00c04fd930c9': 'Application-Site-Settings',
    'ddc790ac-af4d-442a-8f0f-a1d4caa7dd92': 'Application-Version',
    'bf967a80-0de6-11d0-a285-00aa003049e2': 'Attribute-Schema',
    '4bcb2477-4bb3-4545-a9fc-fb66e136b435': 'BootableDevice',
    'bf967a81-0de6-11d0-a285-00aa003049e2': 'Builtin-Domain',
    '7d6c0e9d-7e20-11d0-afd6-00c04fd930c9': 'Category-Registration',
    '3fdfee50-47f4-11d1-a9c3-0000f80367c1': 'Certification-Authority',
    'bf967a82-0de6-11d0-a285-00aa003049e2': 'Class-Registration',
    'bf967a83-0de6-11d0-a285-00aa003049e2': 'Class-Schema',
    'bf967a84-0de6-11d0-a285-00aa003049e2': 'Class-Store',
    'bf967a85-0de6-11d0-a285-00aa003049e2': 'Com-Connection-Point',
    'bf967a86-0de6-11d0-a285-00aa003049e2': 'Computer',
    'bf967a87-0de6-11d0-a285-00aa003049e2': 'Configuration',
    '5cb41ecf-0e4c-11d0-a286-00aa003049e2': 'Connection-Point',
    '5cb41ed0-0e4c-11d0-a286-00aa003049e2': 'Contact',
    'bf967a8b-0de6-11d0-a285-00aa003049e2': 'Container',
    '8297931e-86d3-11d0-afda-00c04fd930c9': 'Control-Access-Right',
    'bf967a8c-0de6-11d0-a285-00aa003049e2': 'Country',
    '167758ca-47f3-11d1-a9c3-0000f80367c1': 'CRL-Distribution-Point',
    'bf967a8d-0de6-11d0-a285-00aa003049e2': 'Cross-Ref',
    'ef9e60e0-56f7-11d1-a9c6-0000f80367c1': 'Cross-Ref-Container',
    'bf967a8e-0de6-11d0-a285-00aa003049e2': 'Device',
    '8447f9f2-1027-11d0-a05f-00aa006c33ed': 'Dfs-Configuration',
    '963d2756-48be-11d1-a9c3-0000f80367c1': 'DHCP-Class',
    'e0fa1e8a-9b45-11d0-afdd-00c04fd930c9': 'Display-Specifier',
    '5fd4250c-1262-11d0-a060-00aa006c33ed': 'Display-Template',
    'bf967a8f-0de6-11d0-a285-00aa003049e2': 'DMD',
    'e0fa1e8c-9b45-11d0-afdd-00c04fd930c9': 'Dns-Node',
    'e0fa1e8b-9b45-11d0-afdd-00c04fd930c9': 'Dns-Zone',
    '696f8a61-2d3f-40ce-a4b3-e275dfcc49c5': 'Dns-Zone-Scope',
    'f2699093-f25a-4220-9deb-03df4cc4a9c5': 'Dns-Zone-Scope-Container',
    '39bad96d-c2d6-4baf-88ab-7e4207600117': 'document',
    '7a2be07c-302f-4b96-bc90-0795d66885f8': 'documentSeries',
    '19195a5a-6da0-11d0-afd3-00c04fd930c9': 'Domain',
    '19195a5b-6da0-11d0-afd3-00c04fd930c9': 'Domain-DNS',
    'bf967a99-0de6-11d0-a285-00aa003049e2': 'Domain-Policy',
    '8bfd2d3d-efda-4549-852c-f85e137aedc6': 'domainRelatedObject',
    '09b10f14-6f93-11d2-9905-0000f87a57d4': 'DS-UI-Settings',
    '3fdfee52-47f4-11d1-a9c3-0000f80367c1': 'DSA',
    '66d51249-3355-4c1f-b24e-81f252aca23b': 'Dynamic-Object',
    'dd712229-10e4-11d0-a05f-00aa006c33ed': 'File-Link-Tracking',
    '8e4eb2ed-4712-11d0-a1a0-00c04fd930c9': 'File-Link-Tracking-Entry',
    '89e31c12-8530-11d0-afda-00c04fd930c9': 'Foreign-Security-Principal',
    'c498f152-dc6b-474a-9f52-7cdba3d7d351': 'friendlyCountry',
    '8447f9f3-1027-11d0-a05f-00aa006c33ed': 'FT-Dfs',
    'bf967a9c-0de6-11d0-a285-00aa003049e2': 'Group',
    'bf967a9d-0de6-11d0-a285-00aa003049e2': 'Group-Of-Names',
    'f30e3bc2-9ff0-11d1-b603-0000f80367c1': 'Group-Policy-Container',
    '0310a911-93a3-4e21-a7a3-55d85ab2c48b': 'groupOfUniqueNames',
    'a699e529-a637-4b7d-a0fb-5dc466a0b8a7': 'IEEE802Device',
    '7bfdcb8a-4807-11d1-a9c3-0000f80367c1': 'Index-Server-Catalog',
    '4828cc14-1437-45bc-9b07-ad6f015e5f28': 'inetOrgPerson',
    '2df90d89-009f-11d2-aa4c-00c04fd7d83a': 'Infrastructure-Update',
    '07383086-91df-11d1-aebc-0000f80367c1': 'Intellimirror-Group',
    '07383085-91df-11d1-aebc-0000f80367c1': 'Intellimirror-SCP',
    '26d97376-6070-11d1-a9c6-0000f80367c1': 'Inter-Site-Transport',
    '26d97375-6070-11d1-a9c6-0000f80367c1': 'Inter-Site-Transport-Container',
    'ab911646-8827-4f95-8780-5a8f008eb68f': 'IpHost',
    'd95836c3-143e-43fb-992a-b057f1ecadf9': 'IpNetwork',
    '9c2dcbd2-fbf0-4dc7-ace0-8356dcd0f013': 'IpProtocol',
    'b40ff825-427a-11d1-a9c2-0000f80367c1': 'Ipsec-Base',
    'b40ff826-427a-11d1-a9c2-0000f80367c1': 'Ipsec-Filter',
    'b40ff828-427a-11d1-a9c2-0000f80367c1': 'Ipsec-ISAKMP-Policy',
    'b40ff827-427a-11d1-a9c2-0000f80367c1': 'Ipsec-Negotiation-Policy',
    'b40ff829-427a-11d1-a9c2-0000f80367c1': 'Ipsec-NFA',
    'b7b13121-b82e-11d0-afee-0000f80367c1': 'Ipsec-Policy',
    '2517fadf-fa97-48ad-9de6-79ac5721f864': 'IpService',
    'bf967a9e-0de6-11d0-a285-00aa003049e2': 'Leaf',
    '1be8f17d-a9ff-11d0-afe2-00c04fd930c9': 'Licensing-Site-Settings',
    'ddac0cf5-af8f-11d0-afeb-00c04fd930c9': 'Link-Track-Object-Move-Table',
    'ddac0cf7-af8f-11d0-afeb-00c04fd930c9': 'Link-Track-OMT-Entry',
    'ddac0cf6-af8f-11d0-afeb-00c04fd930c9': 'Link-Track-Vol-Entry',
    'ddac0cf4-af8f-11d0-afeb-00c04fd930c9': 'Link-Track-Volume-Table',
    'bf967aa0-0de6-11d0-a285-00aa003049e2': 'Locality',
    '52ab8671-5709-11d1-a9c6-0000f80367c1': 'Lost-And-Found',
    'bf967aa1-0de6-11d0-a285-00aa003049e2': 'Mail-Recipient',
    '11b6cc94-48c4-11d1-a9c3-0000f80367c1': 'Meeting',
    '555c21c3-a136-455a-9397-796bbd358e25': 'ms-Authz-Central-Access-Policies',
    'a5679cb0-6f9d-432c-8b75-1e3e834f02aa': 'ms-Authz-Central-Access-Policy',
    '5b4a06dc-251c-4edb-8813-0bdd71327226': 'ms-Authz-Central-Access-Rule',
    '99bb1b7a-606d-4f8b-800e-e15be554ca8d': 'ms-Authz-Central-Access-Rules',
    'c9010e74-4e58-49f7-8a89-5e3e2340fcf8': 'ms-COM-Partition',
    '250464ab-c417-497a-975a-9e0d459a7ca1': 'ms-COM-PartitionSet',
    '25173408-04ca-40e8-865e-3f9ce9bf1bd3': 'ms-DFS-Deleted-Link-v2',
    '7769fb7a-1159-4e96-9ccd-68bc487073eb': 'ms-DFS-Link-v2',
    'da73a085-6e64-4d61-b064-015d04164795': 'ms-DFS-Namespace-Anchor',
    '21cb8628-f3c3-4bbf-bff6-060b2d8f299a': 'ms-DFS-Namespace-v2',
    'e58f972e-64b5-46ef-8d8b-bbc3e1897eab': 'ms-DFSR-Connection',
    '64759b35-d3a1-42e4-b5f1-a3de162109b3': 'ms-DFSR-Content',
    '4937f40d-a6dc-4d48-97ca-06e5fbfd3f16': 'ms-DFSR-ContentSet',
    '7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6': 'ms-DFSR-GlobalSettings',
    'fa85c591-197f-477e-83bd-ea5a43df2239': 'ms-DFSR-LocalSettings',
    '4229c897-c211-437c-a5ae-dbf705b696e5': 'ms-DFSR-Member',
    '1c332fe0-0c2a-4f32-afca-23c5e45a9e77': 'ms-DFSR-ReplicationGroup',
    'e11505d7-92c4-43e7-bf5c-295832ffc896': 'ms-DFSR-Subscriber',
    '67212414-7bcc-4609-87e0-088dad8abdee': 'ms-DFSR-Subscription',
    '04828aa9-6e42-4e80-b962-e2fe00754d17': 'ms-DFSR-Topology',
    'ef2fc3ed-6e18-415b-99e4-3114a8cb124b': 'ms-DNS-Server-Settings',
    '90df3c3e-1854-4455-a5d7-cad40d56657a': 'ms-DS-App-Configuration',
    '9e67d761-e327-4d55-bc95-682f875e2f8e': 'ms-DS-App-Data',
    '3a9adf5d-7b97-4f7e-abb4-e5b55c1c06b4': 'ms-DS-AuthN-Policies',
    'ab6a1156-4dc7-40f5-9180-8e4ce42fe5cd': 'ms-DS-AuthN-Policy',
    'f9f0461e-697d-4689-9299-37e61d617b0d': 'ms-DS-AuthN-Policy-Silo',
    'd2b1470a-8f84-491e-a752-b401ee00fe5c': 'ms-DS-AuthN-Policy-Silos',
    'cfee1051-5f28-4bae-a863-5d0cc18a8ed1': 'ms-DS-Az-Admin-Manager',
    'ddf8de9b-cba5-4e12-842e-28d8b66f75ec': 'ms-DS-Az-Application',
    '860abe37-9a9b-4fa4-b3d2-b8ace5df9ec5': 'ms-DS-Az-Operation',
    '8213eac9-9d55-44dc-925c-e9a52b927644': 'ms-DS-Az-Role',
    '4feae054-ce55-47bb-860e-5b12063a51de': 'ms-DS-Az-Scope',
    '1ed3a473-9b1b-418a-bfa0-3a37b95a5306': 'ms-DS-Az-Task',
    '81a3857c-5469-4d8f-aae6-c27699762604': 'ms-DS-Claim-Type',
    'b8442f58-c490-4487-8a9d-d80b883271ad': 'ms-DS-Claim-Type-Property-Base',
    '36093235-c715-4821-ab6a-b56fb2805a58': 'ms-DS-Claim-Types',
    'c8fca9b1-7d88-bb4f-827a-448927710762': 'ms-DS-Claims-Transformation-Policies',
    '2eeb62b3-1373-fe45-8101-387f1676edc7': 'ms-DS-Claims-Transformation-Policy-Type',
    '641e87a4-8326-4771-ba2d-c706df35e35a': 'ms-DS-Cloud-Extensions',
    '5df2b673-6d41-4774-b3e8-d52e8ee9ff99': 'ms-DS-Device',
    '7c9e8c58-901b-4ea8-b6ec-4eb9e9fc0e11': 'ms-DS-Device-Container',
    '96bc3a1a-e3d2-49d3-af11-7b0df79d67f5': 'ms-DS-Device-Registration-Service',
    '310b55ce-3dcd-4392-a96d-c9e35397c24f': 'ms-DS-Device-Registration-Service-Container',
    '7b8b558a-93a5-4af7-adca-c017e67f1057': 'ms-DS-Group-Managed-Service-Account',
    'ee1f5543-7c2e-476a-8b3f-e11f4af6c498': 'ms-DS-Key-Credential',
    'ce206244-5827-4a86-ba1c-1c0c386c1b64': 'ms-DS-Managed-Service-Account',
    '44f00041-35af-468b-b20a-6ce8737c580b': 'ms-DS-Optional-Feature',
    '3bcd9db8-f84b-451c-952f-6c52b81f9ec6': 'ms-DS-Password-Settings',
    '5b06b06a-4cf3-44c0-bd16-43bc10a987da': 'ms-DS-Password-Settings-Container',
    'da83fc4f-076f-4aea-b4dc-8f4dab9b5993': 'ms-DS-Quota-Container',
    'de91fc26-bd02-4b52-ae26-795999e96fc7': 'ms-DS-Quota-Control',
    '7a4a4584-b350-478f-acd6-b4b852d82cc0': 'ms-DS-Resource-Properties',
    '5b283d5e-8404-4195-9339-8450188c501a': 'ms-DS-Resource-Property',
    '72e3d47a-b342-4d45-8f56-baff803cabf9': 'ms-DS-Resource-Property-List',
    '770f4cb3-1643-469c-b766-edd77aa75e14': 'ms-DS-Shadow-Principal',
    '11f95545-d712-4c50-b847-d2781537c633': 'ms-DS-Shadow-Principal-Container',
    'e3c27fdf-b01d-4f4e-87e7-056eef0eb922': 'ms-DS-Value-Type',
    'd03d6858-06f4-11d2-aa53-00c04fd7d83a': 'ms-Exch-Configuration-Container',
    'ea715d30-8f53-40d0-bd1e-6109186d782c': 'ms-FVE-RecoveryInformation',
    '7b9a2d92-b7eb-4382-9772-c3e0f9baaf94': 'ms-ieee-80211-Policy',
    '1f7c257c-b8a3-4525-82f8-11ccc7bee36e': 'ms-Imaging-PostScanProcess',
    'a0ed2ac1-970c-4777-848e-ec63a0ec44fc': 'ms-Imaging-PSPs',
    'aa02fd41-17e0-4f18-8687-b2239649736b': 'ms-Kds-Prov-RootKey',
    '5ef243a8-2a25-45a6-8b73-08a71ae677ce': 'ms-Kds-Prov-ServerConfiguration',
    '1cb81863-b822-4379-9ea2-5ff7bdc6386d': 'ms-net-ieee-80211-GroupPolicy',
    '99a03a6a-ab19-4446-9350-0cb878ed2d9b': 'ms-net-ieee-8023-GroupPolicy',
    '37cfd85c-6719-4ad8-8f9e-8678ba627563': 'ms-PKI-Enterprise-Oid',
    '26ccf238-a08e-4b86-9a82-a8c9ac7ee5cb': 'ms-PKI-Key-Recovery-Agent',
    '1562a632-44b9-4a7e-a2d3-e426c96a3acc': 'ms-PKI-Private-Key-Recovery-Agent',
    'a16f33c7-7fd6-4828-9364-435138fda08d': 'ms-Print-ConnectionPolicy',
    '51a0e68c-0dc5-43ca-935d-c1c911bf2ee5': 'ms-SPP-Activation-Object',
    'b72f862b-bb25-4d5d-aa51-62c59bdf90ae': 'ms-SPP-Activation-Objects-Container',
    '09f0506a-cd28-11d2-9993-0000f87a57d4': 'MS-SQL-OLAPCube',
    '20af031a-ccef-11d2-9993-0000f87a57d4': 'MS-SQL-OLAPDatabase',
    '0c7e18ea-ccef-11d2-9993-0000f87a57d4': 'MS-SQL-OLAPServer',
    '1d08694a-ccef-11d2-9993-0000f87a57d4': 'MS-SQL-SQLDatabase',
    '17c2f64e-ccef-11d2-9993-0000f87a57d4': 'MS-SQL-SQLPublication',
    '11d43c5c-ccef-11d2-9993-0000f87a57d4': 'MS-SQL-SQLRepository',
    '05f6c878-ccef-11d2-9993-0000f87a57d4': 'MS-SQL-SQLServer',
    'ca7b9735-4b2a-4e49-89c3-99025334dc94': 'ms-TAPI-Rt-Conference',
    '53ea1cb5-b704-4df9-818f-5cb4ec86cac1': 'ms-TAPI-Rt-Person',
    '85045b6a-47a6-4243-a7cc-6890701f662c': 'ms-TPM-Information-Object',
    'e027a8bd-6456-45de-90a3-38593877ee74': 'ms-TPM-Information-Objects-Container',
    '50ca5d7d-5c8b-4ef3-b9df-5b66d491e526': 'ms-WMI-IntRangeParam',
    '292f0d9a-cf76-42b0-841f-b650f331df62': 'ms-WMI-IntSetParam',
    '07502414-fdca-4851-b04a-13645b11d226': 'ms-WMI-MergeablePolicyTemplate',
    '55dd81c9-c312-41f9-a84d-c6adbdf1e8e1': 'ms-WMI-ObjectEncoding',
    'e2bc80f1-244a-4d59-acc6-ca5c4f82e6e1': 'ms-WMI-PolicyTemplate',
    '595b2613-4109-4e77-9013-a3bb4ef277c7': 'ms-WMI-PolicyType',
    '45fb5a57-5018-4d0f-9056-997c8c9122d9': 'ms-WMI-RangeParam',
    '6afe8fe2-70bc-4cce-b166-a96f7359c514': 'ms-WMI-RealRangeParam',
    '3c7e6f83-dd0e-481b-a0c2-74cd96ef2a66': 'ms-WMI-Rule',
    'f1e44bdf-8dd3-4235-9c86-f91f31f5b569': 'ms-WMI-ShadowObject',
    '6cc8b2b5-12df-44f6-8307-e74f5cdee369': 'ms-WMI-SimplePolicyTemplate',
    'ab857078-0142-4406-945b-34c9b6b13372': 'ms-WMI-Som',
    '0bc579a2-1da7-4cea-b699-807f3b9d63a4': 'ms-WMI-StringSetParam',
    'd9a799b2-cef3-48b3-b5ad-fb85f8dd3214': 'ms-WMI-UintRangeParam',
    '8f4beb31-4e19-46f5-932e-5fa03c339b1d': 'ms-WMI-UintSetParam',
    'b82ac26b-c6db-4098-92c6-49c18a3336e1': 'ms-WMI-UnknownRangeParam',
    '05630000-3927-4ede-bf27-ca91f275c26f': 'ms-WMI-WMIGPO',
    '9a0dc344-c100-11d1-bbc5-0080c76670c0': 'MSMQ-Configuration',
    '876d6817-35cc-436c-acea-5ef7174dd9be': 'MSMQ-Custom-Recipient',
    '9a0dc345-c100-11d1-bbc5-0080c76670c0': 'MSMQ-Enterprise-Settings',
    '46b27aac-aafa-4ffb-b773-e5bf621ee87b': 'MSMQ-Group',
    '50776997-3c3d-11d2-90cc-00c04fd91ab1': 'MSMQ-Migrated-User',
    '9a0dc343-c100-11d1-bbc5-0080c76670c0': 'MSMQ-Queue',
    '9a0dc347-c100-11d1-bbc5-0080c76670c0': 'MSMQ-Settings',
    '9a0dc346-c100-11d1-bbc5-0080c76670c0': 'MSMQ-Site-Link',
    '36297dce-656b-4423-ab65-dabb2770819e': 'msSFU-30-Domain-Info',
    'd6710785-86ff-44b7-85b5-f1f8689522ce': 'msSFU-30-Mail-Aliases',
    'e263192c-2a02-48df-9792-94f2328781a0': 'msSFU-30-Net-Id',
    'e15334a3-0bf0-4427-b672-11f5d84acc92': 'msSFU-30-Network-User',
    'faf733d0-f8eb-4dcf-8d75-f1753af6a50b': 'msSFU-30-NIS-Map-Config',
    '7672666c-02c1-4f33-9ecf-f649c1dd9b7c': 'NisMap',
    '72efbf84-6e7b-4a5c-a8db-8a75a7cad254': 'NisNetgroup',
    '904f8a93-4954-4c5f-b1e1-53c097a31e13': 'NisObject',
    '19195a60-6da0-11d0-afd3-00c04fd930c9': 'NTDS-Connection',
    'f0f8ffab-1191-11d0-a060-00aa006c33ed': 'NTDS-DSA',
    '85d16ec1-0791-4bc8-8ab3-70980602ff8c': 'NTDS-DSA-RO',
    '19195a5f-6da0-11d0-afd3-00c04fd930c9': 'NTDS-Service',
    '19195a5d-6da0-11d0-afd3-00c04fd930c9': 'NTDS-Site-Settings',
    '2a132586-9373-11d1-aebc-0000f80367c1': 'NTFRS-Member',
    '5245803a-ca6a-11d0-afff-0000f80367c1': 'NTFRS-Replica-Set',
    'f780acc2-56f0-11d1-a9c6-0000f80367c1': 'NTFRS-Settings',
    '2a132588-9373-11d1-aebc-0000f80367c1': 'NTFRS-Subscriber',
    '2a132587-9373-11d1-aebc-0000f80367c1': 'NTFRS-Subscriptions',
    'cadd1e5e-fefc-4f3f-b5a9-70e994204303': 'OncRpc',
    'bf967aa3-0de6-11d0-a285-00aa003049e2': 'Organization',
    'bf967aa4-0de6-11d0-a285-00aa003049e2': 'Organizational-Person',
    'a8df74bf-c5ea-11d1-bbcb-0080c76670c0': 'Organizational-Role',
    'bf967aa5-0de6-11d0-a285-00aa003049e2': 'Organizational-Unit',
    'bf967aa6-0de6-11d0-a285-00aa003049e2': 'Package-Registration',
    'bf967aa7-0de6-11d0-a285-00aa003049e2': 'Person',
    'b7b13122-b82e-11d0-afee-0000f80367c1': 'Physical-Location',
    'e5209ca2-3bba-11d2-90cc-00c04fd91ab1': 'PKI-Certificate-Template',
    'ee4aa692-3bba-11d2-90cc-00c04fd91ab1': 'PKI-Enrollment-Service',
    'ad44bb41-67d5-4d88-b575-7b20674e76d8': 'PosixAccount',
    '2a9350b8-062c-4ed0-9903-dde10d06deba': 'PosixGroup',
    'bf967aa8-0de6-11d0-a285-00aa003049e2': 'Print-Queue',
    '83cc7075-cca7-11d0-afff-0000f80367c1': 'Query-Policy',
    'bf967aa9-0de6-11d0-a285-00aa003049e2': 'Remote-Mail-Recipient',
    '2a39c5bd-8960-11d1-aebc-0000f80367c1': 'Remote-Storage-Service-Point',
    'a8df74d6-c5ea-11d1-bbcb-0080c76670c0': 'Residential-Person',
    'b93e3a78-cbae-485e-a07b-5ef4ae505686': 'rFC822LocalPart',
    '6617188d-8f3c-11d0-afda-00c04fd930c9': 'RID-Manager',
    '7bfdcb89-4807-11d1-a9c3-0000f80367c1': 'RID-Set',
    '7860e5d2-c8b0-4cbb-bd45-d9455beb9206': 'room',
    '80212842-4bdc-11d1-a9c4-0000f80367c1': 'Rpc-Container',
    'bf967aac-0de6-11d0-a285-00aa003049e2': 'rpc-Entry',
    '88611bdf-8cf4-11d0-afda-00c04fd930c9': 'rpc-Group',
    '88611be1-8cf4-11d0-afda-00c04fd930c9': 'rpc-Profile',
    'f29653cf-7ad0-11d0-afd6-00c04fd930c9': 'rpc-Profile-Element',
    '88611be0-8cf4-11d0-afda-00c04fd930c9': 'rpc-Server',
    'f29653d0-7ad0-11d0-afd6-00c04fd930c9': 'rpc-Server-Element',
    '2a39c5be-8960-11d1-aebc-0000f80367c1': 'RRAS-Administration-Connection-Point',
    'f39b98ae-938d-11d1-aebd-0000f80367c1': 'RRAS-Administration-Dictionary',
    'bf967a90-0de6-11d0-a285-00aa003049e2': 'Sam-Domain',
    'bf967a91-0de6-11d0-a285-00aa003049e2': 'Sam-Domain-Base',
    'bf967aad-0de6-11d0-a285-00aa003049e2': 'Sam-Server',
    'bf967aae-0de6-11d0-a285-00aa003049e2': 'Secret',
    'bf967aaf-0de6-11d0-a285-00aa003049e2': 'Security-Object',
    'bf967ab0-0de6-11d0-a285-00aa003049e2': 'Security-Principal',
    'bf967a92-0de6-11d0-a285-00aa003049e2': 'Server',
    'f780acc0-56f0-11d1-a9c6-0000f80367c1': 'Servers-Container',
    'b7b13123-b82e-11d0-afee-0000f80367c1': 'Service-Administration-Point',
    'bf967ab1-0de6-11d0-a285-00aa003049e2': 'Service-Class',
    '28630ec1-41d5-11d1-a9c1-0000f80367c1': 'Service-Connection-Point',
    'bf967ab2-0de6-11d0-a285-00aa003049e2': 'Service-Instance',
    '5b6d8467-1a18-4174-b350-9cc6e7b4ac8d': 'ShadowAccount',
    '5fe69b0b-e146-4f15-b0ab-c1e5d488e094': 'simpleSecurityObject',
    'bf967ab3-0de6-11d0-a285-00aa003049e2': 'Site',
    'd50c2cde-8951-11d1-aebc-0000f80367c1': 'Site-Link',
    'd50c2cdf-8951-11d1-aebc-0000f80367c1': 'Site-Link-Bridge',
    '7a4117da-cd67-11d0-afff-0000f80367c1': 'Sites-Container',
    'bf967ab5-0de6-11d0-a285-00aa003049e2': 'Storage',
    'b7b13124-b82e-11d0-afee-0000f80367c1': 'Subnet',
    'b7b13125-b82e-11d0-afee-0000f80367c1': 'Subnet-Container',
    '5a8b3261-c38d-11d1-bbc9-0080c76670c0': 'SubSchema',
    'bf967ab7-0de6-11d0-a285-00aa003049e2': 'Top',
    'bf967ab8-0de6-11d0-a285-00aa003049e2': 'Trusted-Domain',
    '281416e2-1968-11d0-a28f-00aa003049e2': 'Type-Library',
    'bf967aba-0de6-11d0-a285-00aa003049e2': 'User',
    'bf967abb-0de6-11d0-a285-00aa003049e2': 'Volume',
}


@enum.unique
class SecurityDescriptorControlFlag(enum.IntFlag):
    """Security Descriptor control flags"""
    SE_OWNER_DEFAULTED = 0x0001
    SE_GROUP_DEFAULTED = 0x0002
    SE_DACL_PRESENT = 0x0004
    SE_DACL_DEFAULTED = 0x0008
    SE_SACL_PRESENT = 0x0010
    SE_SACL_DEFAULTED = 0x0020
    SE_DACL_TRUSTED = 0x0040
    SE_SERVER_SECURITY = 0x0080
    SE_DACL_AUTO_INHERIT_REQ = 0x0100
    SE_SACL_AUTO_INHERIT_REQ = 0x0200
    SE_DACL_AUTO_INHERITED = 0x0400
    SE_SACL_AUTO_INHERITED = 0x0800
    SE_DACL_PROTECTED = 0x1000
    SE_SACL_PROTECTED = 0x2000
    SE_RM_CONTROL_VALID = 0x4000
    SE_SELF_RELATIVE = 0x8000


# Abbreviations for Security Descriptor control flags, for use in SDDL
SEC_DESC_CTRL_FLAG_ABBREV: Mapping[SecurityDescriptorControlFlag, str] = {
    SecurityDescriptorControlFlag.SE_OWNER_DEFAULTED: 'OD',
    SecurityDescriptorControlFlag.SE_GROUP_DEFAULTED: 'GD',
    SecurityDescriptorControlFlag.SE_DACL_PRESENT: 'DP',
    SecurityDescriptorControlFlag.SE_DACL_DEFAULTED: 'DD',
    SecurityDescriptorControlFlag.SE_SACL_PRESENT: 'SP',
    SecurityDescriptorControlFlag.SE_SACL_DEFAULTED: 'SD',
    SecurityDescriptorControlFlag.SE_DACL_TRUSTED: 'DT',
    SecurityDescriptorControlFlag.SE_SERVER_SECURITY: 'SS',
    SecurityDescriptorControlFlag.SE_DACL_AUTO_INHERIT_REQ: 'DC',
    SecurityDescriptorControlFlag.SE_SACL_AUTO_INHERIT_REQ: 'SC',
    SecurityDescriptorControlFlag.SE_DACL_AUTO_INHERITED: 'DI',
    SecurityDescriptorControlFlag.SE_SACL_AUTO_INHERITED: 'SI',
    SecurityDescriptorControlFlag.SE_DACL_PROTECTED: 'PD',
    SecurityDescriptorControlFlag.SE_SACL_PROTECTED: 'PS',
    SecurityDescriptorControlFlag.SE_RM_CONTROL_VALID: 'RM',
    SecurityDescriptorControlFlag.SE_SELF_RELATIVE: 'SR',
}

assert len(SEC_DESC_CTRL_FLAG_ABBREV) == 16  # 16 bits


@enum.unique
class AceType(enum.IntFlag):
    """Security Descriptor Access Control Entry types"""
    ACCESS_ALLOWED_ACE_TYPE = 0x0
    ACCESS_DENIED_ACE_TYPE = 0x1
    SYSTEM_AUDIT_ACE_TYPE = 0x2
    SYSTEM_ALARM_ACE_TYPE = 0x3
    ACCESS_ALLOWED_COMPOUND_ACE_TYPE = 0x4
    ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x5
    ACCESS_DENIED_OBJECT_ACE_TYPE = 0x6
    SYSTEM_AUDIT_OBJECT_ACE_TYPE = 0x7
    SYSTEM_ALARM_OBJECT_ACE_TYPE = 0x8
    ACCESS_ALLOWED_CALLBACK_ACE_TYPE = 0x9
    ACCESS_DENIED_CALLBACK_ACE_TYPE = 0xa
    ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE = 0xb
    ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE = 0xc
    SYSTEM_AUDIT_CALLBACK_ACE_TYPE = 0xd
    SYSTEM_ALARM_CALLBACK_ACE_TYPE = 0xe
    SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE = 0xf
    SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE = 0x10
    SYSTEM_MANDATORY_LABEL_ACE_TYPE = 0x11
    SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE = 0x12
    SYSTEM_SCOPED_POLICY_ID_ACE_TYPE = 0x13


# Abbreviations for ACE types, for use in SDDL
ACE_TYPE_ABBREV: Mapping[AceType, str] = {
    AceType.ACCESS_ALLOWED_ACE_TYPE: 'A',
    AceType.ACCESS_DENIED_ACE_TYPE: 'D',
    AceType.SYSTEM_AUDIT_ACE_TYPE: 'AU',
    AceType.SYSTEM_ALARM_ACE_TYPE: 'AL',
    AceType.ACCESS_ALLOWED_COMPOUND_ACE_TYPE: 'ac?',  # Unknown?
    AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE: 'OA',
    AceType.ACCESS_DENIED_OBJECT_ACE_TYPE: 'OD',
    AceType.SYSTEM_AUDIT_OBJECT_ACE_TYPE: 'OU',
    AceType.SYSTEM_ALARM_OBJECT_ACE_TYPE: 'OL',
    AceType.ACCESS_ALLOWED_CALLBACK_ACE_TYPE: 'XA',
    AceType.ACCESS_DENIED_CALLBACK_ACE_TYPE: 'XD',
    AceType.ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE: 'ZA',
    AceType.ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE: 'zd?',  # Unknown?
    AceType.SYSTEM_AUDIT_CALLBACK_ACE_TYPE: 'XU',
    AceType.SYSTEM_ALARM_CALLBACK_ACE_TYPE: 'xl?',  # Unknown?
    AceType.SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE: 'zu?',  # Unknown?
    AceType.SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE: 'zl?',  # Unknown?
    AceType.SYSTEM_MANDATORY_LABEL_ACE_TYPE: 'ML',
    AceType.SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE: 'RA',
    AceType.SYSTEM_SCOPED_POLICY_ID_ACE_TYPE: 'SP',
}


@enum.unique
class AceFlag(enum.IntFlag):
    """Security Descriptor Access Control Entry flags"""
    OBJECT_INHERIT_ACE = 0x1
    CONTAINER_INHERIT_ACE = 0x2
    NO_PROPAGATE_INHERIT_ACE = 0x4
    INHERIT_ONLY_ACE = 0x8
    INHERITED_ACE = 0x10
    UNDEFINED_20 = 0x20
    SUCCESSFUL_ACCESS_ACE_FLAG = 0x40  # for SACL
    FAILED_ACCESS_ACE_FLAG = 0x80  # for SACL


# Abbreviations for ACE flags, for use in SDDL
ACE_FLAG_ABBREV: Mapping[AceFlag, str] = {
    AceFlag.OBJECT_INHERIT_ACE: 'OI',
    AceFlag.CONTAINER_INHERIT_ACE: 'CI',
    AceFlag.NO_PROPAGATE_INHERIT_ACE: 'NP',
    AceFlag.INHERIT_ONLY_ACE: 'IO',
    AceFlag.INHERITED_ACE: 'ID',
    AceFlag.UNDEFINED_20: '20?',  # Not defined
    AceFlag.SUCCESSFUL_ACCESS_ACE_FLAG: 'SA',
    AceFlag.FAILED_ACCESS_ACE_FLAG: 'FA',
}


assert len(ACE_FLAG_ABBREV) == 8  # 8 bits


class SecurityDescriptorRelative(ctypes.LittleEndianStructure):
    """struct SECURITY_DESCRIPTOR_RELATIVE"""
    _fields_ = (
        ('Revision', ctypes.c_uint8),
        ('Sbz1', ctypes.c_uint8),
        ('Control', ctypes.c_uint16),
        ('Owner', ctypes.c_uint32),
        ('Group', ctypes.c_uint32),
        ('Sacl', ctypes.c_uint32),
        ('Dacl', ctypes.c_uint32),
    )


assert ctypes.sizeof(SecurityDescriptorRelative) == 0x14


class AclHeader(ctypes.LittleEndianStructure):
    """struct ACL"""
    _fields_ = (
        ('AclRevision', ctypes.c_uint8),
        ('Sbz1', ctypes.c_uint8),
        ('AclSize', ctypes.c_uint16),
        ('AceCount', ctypes.c_uint16),
        ('Sbz2', ctypes.c_uint16),
    )


assert ctypes.sizeof(AclHeader) == 8


class Sid:
    """Parse a Security Identifier, like structure SID"""
    def __init__(self, data: bytes):
        self.revision: int = data[0]
        self.sub_authority_count: int = data[1]
        # Decode a 6-bytes integer in Big Endian, for the identifier authority
        self.identifier_authority: int = sum(x << (8 * i) for i, x in enumerate(data[7:2:-1]))
        self.sub_authority: Tuple[int, ...] = struct.unpack(
            f'<{self.sub_authority_count}I', data[8:8 + 4 * self.sub_authority_count])

        if self.revision != 1:
            raise ValueError(f"Unexpected SID revision {self.revision}")

    def raw_string(self) -> str:
        """Generate a string such as S-1-5-18, even for well-known SIDs"""
        result = f'S-{self.revision}-{self.identifier_authority}'
        if self.sub_authority:
            result += ''.join(f'-{x}' for x in self.sub_authority)
        return result

    def __str__(self) -> str:
        raw_sid = self.raw_string()
        # Return a well-known SID abbreviation, if it exists
        wksid = WELL_KNOWN_SIDS.get(raw_sid)
        if wksid:
            return f"{wksid[0]} ({wksid[1]})"
        # Return the local SID, if it exists
        local_sid = LOCAL_SIDS.get(raw_sid)
        if local_sid:
            return f"{raw_sid} ({local_sid})"
        return raw_sid

    def __repr__(self) -> str:
        return f"Sid({str(self)!r})"


# Access mask constants, in resolution order from the most likely to the lesser ones
# (each "resolution" drops the bits in the remaining number)
# The 3rd field is the kind of object that is considered for the analyzed access mask
# (A=Active Directory, F=File, D=Directory, K=Registry Key, L=Mandatory Label in SACL)
ACCESS_MASK_CONSTS: Tuple[Tuple[int, str, str], ...] = (
    (0x80000000, 'GR', ''),  # GENERIC_READ
    (0x40000000, 'GW', ''),  # GENERIC_WRITE
    (0x20000000, 'GX', ''),  # GENERIC_EXECUTE
    (0x10000000, 'GA', ''),  # GENERIC_ALL
    (0x02000000, 'MA', ''),  # MAXIMUM_ALLOWED
    (0x01000000, 'AS', ''),  # ACCESS_SYSTEM_SECURITY
    (0x00100000, 'SY', ''),  # SYNCHRONIZE
    (0x00080000, 'WO', ''),  # WRITE_OWNER
    (0x00040000, 'WD', ''),  # WRITE_DAC
    (0x00020000, 'RC', ''),  # READ_CONTROL
    (0x00010000, 'SD', ''),  # (STANDARD_) DELETE

    (0x001f01ff, 'FA', 'F'),  # FILE_ALL_ACCESS
    (0x001201bf, 'FRFWFX', 'F'),
    (0x00120089, 'FR', 'F'),  # FILE_GENERIC_READ
    (0x00120116, 'FW', 'F'),  # FILE_GENERIC_WRITE
    (0x001200a0, 'FX', 'F'),  # FILE_GENERIC_EXECUTE
    (0x00000001, 'Frd', 'F'),  # FILE_READ_DATA
    (0x00000002, 'Fwd', 'F'),  # FILE_WRITE_DATA
    (0x00000004, 'Fad', 'F'),  # FILE_APPEND_DATA
    (0x00000008, 'Fre', 'F'),  # FILE_READ_EA
    (0x00000010, 'Fwe', 'F'),  # FILE_WRITE_EA
    (0x00000020, 'Fx', 'F'),  # FILE_EXECUTE
    (0x00000040, 'Fdc', 'F'),  # FILE_DELETE_CHILD
    (0x00000080, 'Fra', 'F'),  # FILE_READ_ATTRIBUTES
    (0x00000100, 'Fwa', 'F'),  # FILE_WRITE_ATTRIBUTES

    (0x001f01ff, 'FA', 'D'),  # FILE_ALL_ACCESS
    (0x00120089, 'FR', 'D'),  # FILE_GENERIC_READ
    (0x00120116, 'FW', 'D'),  # FILE_GENERIC_WRITE
    (0x001200a0, 'FX', 'D'),  # FILE_GENERIC_EXECUTE
    (0x00000001, 'Fld', 'D'),  # FILE_LIST_DIRECTORY
    (0x00000002, 'Faf', 'D'),  # FILE_ADD_FILE
    (0x00000004, 'Fas', 'D'),  # FILE_ADD_SUBDIRECTORY

    (0x000f003f, 'KA', 'K'),  # KEY_ALL_ACCESS
    (0x00020019, 'KR', 'K'),  # KEY_READ
    (0x00020006, 'KW', 'K'),  # KEY_WRITE
    (0x00000001, 'Kqv', 'K'),  # KEY_QUERY_VALUE
    (0x00000002, 'Ksv', 'K'),  # KEY_SET_VALUE
    (0x00000004, 'Kcs', 'K'),  # KEY_CREATE_SUB_KEY
    (0x00000008, 'Kes', 'K'),  # KEY_ENUMERATE_SUB_KEYS
    (0x00000010, 'Kn', 'K'),  # KEY_NOTIFY
    (0x00000020, 'Kcl', 'K'),  # KEY_CREATE_LINK

    (0x00000001, 'CC', 'A'),  # ADS_RIGHT_DS_CREATE_CHILD
    (0x00000002, 'DC', 'A'),  # ADS_RIGHT_DS_DELETE_CHILD
    (0x00000004, 'LC', 'A'),  # ADS_RIGHT_ACTRL_DS_LIST
    (0x00000008, 'SW', 'A'),  # ADS_RIGHT_DS_SELF
    (0x00000010, 'RP', 'A'),  # ADS_RIGHT_DS_READ_PROP
    (0x00000020, 'WP', 'A'),  # ADS_RIGHT_DS_WRITE_PROP
    (0x00000040, 'DT', 'A'),  # ADS_RIGHT_DS_DELETE_TREE
    (0x00000080, 'LO', 'A'),  # ADS_RIGHT_DS_LIST_OBJECT
    (0x00000100, 'CR', 'A'),  # ADS_RIGHT_DS_CONTROL_ACCESS

    (0x00000001, 'NW', 'M'),  # SYSTEM_MANDATORY_LABEL_NO_WRITE_UP
    (0x00000002, 'NR', 'M'),  # SYSTEM_MANDATORY_LABEL_NO_READ_UP
    (0x00000004, 'NX', 'M'),  # SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP
)


def abbrev_access_mask(access_mask: int, objkind: str) -> str:
    """Get an abbreviation that describes the access mask"""
    if access_mask == 0:
        return ''
    result = ''
    for mask, abbrev, mask_kind in ACCESS_MASK_CONSTS:
        if mask_kind and mask_kind != objkind:
            # Ignore bit masks that do not match the kind
            continue
        if (access_mask & mask) == mask:
            result += abbrev
            access_mask &= ~mask
            if access_mask == 0:
                return result
    return result + f"{access_mask:#010x}"


class SecurityAce:
    """Security Access Control Entry"""
    def __init__(self, ace_type: int, ace_flags: int, ace_data: bytes, objkind: str):
        self.ace_type = AceType(ace_type)
        self.ace_flags = ace_flags
        self.ace_data = ace_data

        self.ace_type_abbrev: str = ACE_TYPE_ABBREV.get(self.ace_type, self.ace_type.name)

        self.flags_desc = ''
        for bitnum in range(8):
            if self.ace_flags & (1 << bitnum):
                self.flags_desc += ACE_FLAG_ABBREV[AceFlag(1 << bitnum)]

        if self.ace_type in (
                AceType.ACCESS_ALLOWED_ACE_TYPE,
                AceType.ACCESS_DENIED_ACE_TYPE,
                AceType.SYSTEM_AUDIT_ACE_TYPE,
                AceType.SYSTEM_MANDATORY_LABEL_ACE_TYPE,
                ):
            # Format: ACE_HEADER (4 bytes), ACCESS_MASK (4 bytes), trustee (SID)
            access_mask = struct.unpack('<I', ace_data[:4])[0]
            trustee = Sid(ace_data[4:])
            self.desc_data = f"{abbrev_access_mask(access_mask, objkind)};{trustee}"
            return

        if self.ace_type in (
                AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE,
                AceType.ACCESS_DENIED_OBJECT_ACE_TYPE,
                ):
            # Format: ACE_HEADER (4 bytes), ACCESS_MASK (4 bytes), flags,
            # optional object type (GUID), optional inherited type (GUID), trustee (SID)
            access_mask, flags = struct.unpack('<II', ace_data[:8])
            offset = 8
            self.desc_data = f"{abbrev_access_mask(access_mask, objkind)};"
            if flags & 1:  # Object type exists
                object_type = str(uuid.UUID(bytes_le=ace_data[offset:offset + 0x10]))
                object_type_desc = CONTROL_ACCESS_RIGHTS_GUID.get(object_type)
                if object_type_desc:
                    object_type_desc = f"CtrAccRgt:{object_type_desc}"
                else:
                    object_type_desc = ATTRIBUTES_BY_GUID.get(object_type)
                    if object_type_desc:
                        object_type_desc = f"Attr:{object_type_desc}"
                    else:
                        object_type_desc = CLASSES_BY_GUID.get(object_type)
                        if object_type_desc:
                            object_type_desc = f"Cls:{object_type_desc}"
                        else:
                            logger.warning("Unknown object type GUID %r", object_type)
                if object_type_desc:
                    object_type += f" ({object_type_desc})"
                self.desc_data += object_type
                offset += 0x10
            self.desc_data += ";"
            if flags & 2:  # Inherited type exists
                inherited_type = uuid.UUID(bytes_le=ace_data[offset:offset + 0x10])
                self.desc_data += str(inherited_type)
                offset += 0x10
            trustee = Sid(ace_data[offset:])
            self.desc_data += f";{trustee}"
            return

        # By default, represent the data as hexadecimal
        self.desc_data = binascii.hexlify(self.ace_data).decode('ascii')

    def __str__(self) -> str:
        return f"{self.ace_type_abbrev};{self.flags_desc};{self.desc_data}"

    def __repr__(self) -> str:
        return f"Ace({str(self)!r})"


class SecurityAcl:
    """Parse a Security Access Control List"""
    def __init__(self, data: bytes, objkind: str):
        self.header: AclHeader = AclHeader.from_buffer_copy(data)
        if self.header.AclRevision not in (2, 4):
            # Revision 2 is ACL_REVISION
            # Revision 4 is ACL_REVISION_DS
            raise ValueError(f"Unexpected security ACL revision {self.header.AclRevision}")
        if self.header.Sbz1 != 0:
            raise ValueError(f"Unexpected security ACL SBZ1 {self.header.Sbz1}")
        if self.header.Sbz2 != 0:
            raise ValueError(f"Unexpected security ACL SBZ2 {self.header.Sbz1}")
        if len(data) < self.header.AclSize:
            raise ValueError(f"Truncated security ACL: {len(data)} < {self.header.AclSize}")

        # Truncate the data to the appropriate size
        data = data[:self.header.AclSize]
        offset = 8
        self.entries: List[SecurityAce] = []
        for _ace_index in range(self.header.AceCount):
            # ACE header is 4-byte long
            ace_type, ace_flags, ace_size = struct.unpack('<BBH', data[offset:offset + 4])
            self.entries.append(SecurityAce(ace_type, ace_flags, data[offset + 4:offset + ace_size], objkind))
            offset += ace_size
        if offset != self.header.AclSize:
            raise ValueError(f"Mismatched ACL size: {offset} != {self.header.AclSize}")

    def __str__(self) -> str:
        return "".join(f"({ace})" for ace in self.entries)

    def __repr__(self) -> str:
        return f"Acl({str(self)!r})"


class SecurityDescriptor:
    """Parse a Security Descriptor"""
    def __init__(self, data: bytes, objkind: str):
        self.raw_data = data
        self.header: SecurityDescriptorRelative = SecurityDescriptorRelative.from_buffer_copy(data)
        if self.header.Revision != 1:
            raise ValueError(f"Unexpected security descriptor revision {self.header.Revision}")
        if self.header.Sbz1 != 0:
            # SBZ is Should-be-Zero
            raise ValueError(f"Unexpected security descriptor SBZ {self.header.Sbz1}")

        self.header_ctrl_desc = ''
        for bitnum in range(16):
            if self.header.Control & (1 << bitnum):
                bit_obj = SecurityDescriptorControlFlag(1 << bitnum)
                self.header_ctrl_desc += SEC_DESC_CTRL_FLAG_ABBREV[bit_obj]

        if self.header.Owner == 0:
            self.owner: Optional[Sid] = None
        else:
            self.owner = Sid(data[self.header.Owner:])

        if self.header.Group == 0:
            self.group: Optional[Sid] = None
        else:
            self.group = Sid(data[self.header.Group:])

        if self.header.Dacl == 0:
            self.dacl: Optional[SecurityAcl] = None
        else:
            self.dacl = SecurityAcl(data[self.header.Dacl:], objkind)

        if self.header.Sacl == 0:
            self.sacl: Optional[SecurityAcl] = None
        else:
            self.sacl = SecurityAcl(data[self.header.Sacl:], objkind)

    @classmethod
    def from_hex(cls, hexdata: str, objkind: str) -> 'SecurityDescriptor':
        return cls(binascii.unhexlify(hexdata), objkind)

    def to_sddl(self) -> str:
        """Represent as SDDL"""
        parts = []
        if self.owner:
            parts.append(f"O={self.owner}")
        if self.group:
            parts.append(f"G={self.group}")
        if self.header.Dacl:
            parts.append(f"D={self.dacl}")
        if self.header.Sacl:
            parts.append(f"S={self.sacl}")
        return " ".join(parts)

    def __repr__(self) -> str:
        return f"SecurityDescriptor({self.to_sddl()!r})"


TableRow = NewType('TableRow', Dict[str, Any])
TableContent = NewType('TableContent', List[TableRow])


@attr.s(auto_attribs=True, frozen=True)
class TableDesc:
    name: str = attr.ib()
    name_no_domain: str = attr.ib()
    path: Path = attr.ib()
    column_names: List[str] = attr.ib()
    column_types: List[Callable[[str], Any]] = attr.ib()

    def load(self) -> TableContent:
        """Load a table"""
        rows: List[TableRow] = []
        with self.path.open('r', encoding='utf-16') as stream:
            for line in stream:
                fields = line.rstrip('\n').split('\t')
                columns = TableRow(collections.OrderedDict(
                    (name, ty(val)) for name, ty, val in zip(self.column_names, self.column_types, fields)
                ))
                rows.append(columns)
        return TableContent(rows)


class OradadTables:
    """Collected tables"""
    def __init__(self, directory: Path):
        self.directory: Path = directory
        self.root_dns_and_date: Optional[str] = None
        self.tables: Dict[str, TableDesc] = {}
        self.tables_by_nodomain: Dict[str, List[str]] = {}
        self.table_content: Dict[str, TableContent] = {}

        logger.info("Decoding %s", directory)

        # Enumerate all tables
        with (directory / 'tables.tsv').open('r') as stream:
            for lineno, line in enumerate(stream, start=1):
                if lineno == 1:
                    self.root_dns_and_date = line.rstrip('\n')
                    logger.debug("Loading dump %r", self.root_dns_and_date)
                    assert '\t' not in self.root_dns_and_date
                    continue
                fields = line.rstrip('\n').split('\t')
                file_path = self.directory / fields[0].replace('\\', '/')
                table_name = fields[1]
                table_name_no_domain = fields[2]
                num_columns = int(fields[3])
                assert len(fields) == 4 + 2 * num_columns
                column_names = [fields[4 + 2 * i] for i in range(num_columns)]

                def map_type_name_to_python(type_name: str) -> Callable[[str], Any]:
                    if type_name in ('bigint', 'int', 'tinyint'):
                        return lambda x: int(x) if x else None
                    if type_name == 'datetime2':
                        return str
                    if type_name == 'uniqueidentifier':
                        return str
                    if type_name.startswith(('varchar(', 'nvarchar(')):
                        return str
                    raise NotImplementedError(f"Unimplemented SQL type {repr(type_name)}")

                column_types = [map_type_name_to_python(fields[5 + 2 * i]) for i in range(num_columns)]

                assert table_name not in self.tables
                self.tables[table_name] = TableDesc(
                    name=table_name,
                    name_no_domain=table_name_no_domain,
                    path=file_path,
                    column_names=column_names,
                    column_types=column_types,
                )
                if table_name_no_domain not in self.tables_by_nodomain:
                    self.tables_by_nodomain[table_name_no_domain] = [table_name]
                else:
                    self.tables_by_nodomain[table_name_no_domain].append(table_name)

    def get_table(self, table_name: str) -> TableContent:
        content = self.table_content.get(table_name)
        if content is not None:
            return content
        content = self.tables[table_name].load()
        logger.debug("Loaded table %r (%d rows)", table_name, len(content))
        self.table_content[table_name] = content
        return content


def main(argv=None):
    parser = argparse.ArgumentParser(description="Decode an ORADAD dump")
    parser.add_argument('directory', metavar="DIRECTORY", type=Path,
                        help="directory of the extracted dump (like ./mydomain/19700101-133742)")
    parser.add_argument('-d', '--debug', action='store_true',
                        help="show debug messages")
    parser.add_argument('-m', '--members', action='store_true',
                        help="show group memberships")
    args = parser.parse_args(argv)

    logging.basicConfig(format='[%(levelname)s] %(message)s',
                        level=logging.DEBUG if args.debug else logging.INFO)

    show_members: bool = args.members

    directory = args.directory
    collect = OradadTables(directory)
    logger.info("Loaded %d tables", len(collect.tables))

    # Load attributes that are defined in the schema
    for table_name in collect.tables_by_nodomain.get('schema_attribute', []):
        for row in collect.get_table(table_name):
            cn = row['cn']
            dn = row['dn']
            assert dn.startswith(f"CN={cn},CN=Schema,CN=Configuration,")
            assert re.match(r'^([0-9a-zA-Z_-]+)$', cn), f"Unexpected CN {cn!r}"
            guid = row['schemaIDGUID'].lower()
            if not re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', guid):
                # Sometimes, the GUID is given in hexadecimal
                if re.match(r'^[0-9a-fA-F]+$', guid):
                    guid = str(uuid.UUID(bytes_le=binascii.unhexlify(guid)))
                else:
                    raise ValueError(f"Unexpected GUID for attribute {cn!r}: {guid!r}")
            if guid not in ATTRIBUTES_BY_GUID:
                logger.debug("Adding schema attribute %r: %r", dn, guid)
                ATTRIBUTES_BY_GUID[guid] = cn
            elif ATTRIBUTES_BY_GUID[guid] != cn:
                # There has been some unfortunate errors in the past
                if guid == 'd999b030-feed-4975-b807-eba444da79e9' and cn == 'ms-Kds-SecretAgreement-Param':
                    pass
                else:
                    logger.warning("Conflicting schema attribute for %r: %r vs %r",
                                   guid, ATTRIBUTES_BY_GUID[guid], cn)

    # Load classes that are defined in the schema
    for table_name in collect.tables_by_nodomain.get('schema_class', []):
        for row in collect.get_table(table_name):
            cn = row['cn']
            dn = row['dn']
            assert dn.startswith(f"CN={cn},CN=Schema,CN=Configuration,")
            assert re.match(r'^([0-9a-zA-Z_-]+)$', cn), f"Unexpected CN {cn!r}"
            guid = row['schemaIDGUID'].lower()
            if not re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', guid):
                if re.match(r'^[0-9a-fA-F]+$', guid):
                    guid = str(uuid.UUID(bytes_le=binascii.unhexlify(guid)))
                else:
                    raise ValueError(f"Unexpected GUID for class {cn!r}: {guid!r}")
            if guid not in CLASSES_BY_GUID:
                logger.debug("Adding schema class %r: %r", dn, guid)
                CLASSES_BY_GUID[guid] = cn
            elif CLASSES_BY_GUID[guid] != cn:
                logger.warning("Conflicting schema class for %r: %r vs %r",
                               guid, CLASSES_BY_GUID[guid], cn)

    # Load control access rights that are defined in the schema
    for table_name in collect.tables_by_nodomain.get('configuration_controlAccessRight', []):
        for row in collect.get_table(table_name):
            guid = row['rightsGuid'].lower()
            dn = row['dn']
            matches = re.match(r'^CN=([0-9a-zA-Z_-]+),CN=Extended-Rights,CN=Configuration,', dn)
            assert matches, f"Unexpected DN {dn!r}"
            cn = matches.group(1)
            if not re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', guid):
                if re.match(r'^[0-9a-fA-F]+$', guid):
                    guid = str(uuid.UUID(bytes_le=binascii.unhexlify(guid)))
                else:
                    raise ValueError(f"Unexpected GUID for control access right {cn!r}: {guid!r}")
            if guid not in CONTROL_ACCESS_RIGHTS_GUID:
                logger.debug("Adding control access rights %r: %r", dn, guid)
                CONTROL_ACCESS_RIGHTS_GUID[guid] = cn
            elif CONTROL_ACCESS_RIGHTS_GUID[guid] != cn:
                # There is a GUID assignment conflict in the official documentation
                if guid == '72e39547-7b18-11d1-adef-00c04fd8d5cd' and \
                        cn in ('DNS-Host-Name-Attributes', 'Validated-DNS-Host-Name'):
                    pass
                else:
                    logger.warning("Conflicting access right for %r: %r vs %r",
                                   guid, CONTROL_ACCESS_RIGHTS_GUID[guid], cn)

    # Gather all local SIDs
    for table_name, table in sorted(collect.tables.items()):
        if 'objectSid' not in table.column_names:
            continue
        for row in collect.get_table(table_name):
            dn = row['dn']
            obj_sid = row.get('objectSid')
            assert re.match(r'^S-1-[0-9-]+[0-9]$', obj_sid), f"Unexpected object SID {obj_sid!r}"

            matches = re.match(r'^CN=([^,=]+),', dn)
            if matches:
                cn = matches.group(1)
                # Sometimes the CN is the SID, in which case use the DN
                if cn == obj_sid:
                    if dn.startswith(f"CN={cn},CN=ForeignSecurityPrincipals,"):
                        cn = f"{cn} [@ForeignSecurityPrincipals]"
                    else:
                        cn = dn
            else:
                # Maybe directly a DC tree
                assert dn.startswith('DC='), f"Unexpected DN {dn!r} for SID"
                cn = dn
            if obj_sid not in LOCAL_SIDS:
                logger.debug("Adding object SID %r: %r", dn, obj_sid)
                LOCAL_SIDS[obj_sid] = cn
            elif LOCAL_SIDS[obj_sid] != cn:
                logger.warning("Conflicting object SID %r: %r vs %r",
                               obj_sid, LOCAL_SIDS[obj_sid], cn)
    logger.info("Loaded %d local SIDs", len(LOCAL_SIDS))

    # Dump all the tables with a security descriptor in their fields
    print("Tables with nTSecurityDescriptor:")
    for table_name, table in sorted(collect.tables.items()):
        have_secdesc = 'nTSecurityDescriptor' in table.column_names
        have_member = show_members and ('member' in table.column_names)
        if not have_secdesc and not have_member:
            continue
        rows = collect.get_table(table_name)
        if len(rows) == 0:
            continue
        print(f"  [{len(rows):4d} rows] {repr(table_name)} ({repr(collect.tables[table_name].name_no_domain)})")
        if table_name == 'metadata':
            continue
        for row in collect.get_table(table_name):
            print(f"    {row['dn']!r}:")

            obj_sid = row.get('objectSid')
            if obj_sid:
                wk_obj_sid = WELL_KNOWN_SIDS.get(obj_sid)
                if wk_obj_sid:
                    print(f"      Object SID: {obj_sid}: {wk_obj_sid[0]} ({wk_obj_sid[1]})")
                else:
                    print(f"      Object SID: {obj_sid}")

            if have_member:
                members = [m for m in row['member'].split(';') if m]
                if not members:
                    print(f"      (no members)")
                elif len(members) == 1:
                    print(f"      members (1): {members[0]}")
                else:
                    print(f"      members ({len(members)}):")
                    for member in members:
                        print(f"        {member}")

            if have_secdesc:
                ntsecdesc = row['nTSecurityDescriptor']
                if not ntsecdesc:
                    print(f"      (empty security descriptor)")
                else:
                    secdesc = SecurityDescriptor.from_hex(ntsecdesc, 'A')
                    # print(f"        {secdesc!r}")
                    if secdesc.owner:
                        print(f"      Owner: {secdesc.owner}")
                    if secdesc.group:
                        print(f"      Group: {secdesc.owner}")
                    if secdesc.dacl:
                        print(f"      DACL: {len(secdesc.dacl.entries)} ACE")
                        for ace in secdesc.dacl.entries:
                            print(f"        {ace}")
                    if secdesc.sacl:
                        print(f"      SACL: {secdesc.sacl}")
                        # Please improve the formatting when this occurs
                        raise NotImplementedError("I have never seen SACL in Active Directory")
            print("")
    print("")


if __name__ == '__main__':
    sys.exit(main())
