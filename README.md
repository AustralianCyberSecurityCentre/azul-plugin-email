# Azul Plugin Email

Plugins to parse, extract attachments and feature email properties.

Handles processing email content either MIME encoded or Outlook OLE2 messages.

Any attachments are extracted as children and mail headers/properties raised
as features.

## Development Installation

To install azul-plugin-email for development run the command
(from the root directory of this project):

```bash
pip install -e .
```

## Usage: azul-olemail

Usage on local files:

```
azul-plugin-olemail test.msg
```

Example Output:

```
----- OleMail results -----
OK

Output features:
                mail_timezone: +0200
        mail_extension_header: X-Proofpoint-Spam-Details
                               X-Proofpoint-Virus-Version
                               X-Received
                    mail_from: Foo Bar <foobar@gmail.com>
                  mail_domain: gmail.com
                               me.com
                      mail_to: foobar@me.com
                      mail_cc: Foo Bar <foobar@gmail.com>
                 mail_address: foobar@me.com
                               foobar@gmail.com
                 mail_subject: Test for TIF files
              mail_message_id: <CADtJ4eNjQSkGcBtVteCiTF+YFG89+AcHxK3QZ=-Mt48xygkvdQ@mail.gmail.com>
               mime_part_hash: 3b43fdeca80da38c80e918e8f21cbd6fc925dac994f3922c7893fc6c1326fb92
                               6f36cb718943751db9dc4c9df624c4390d8a13674127b7e919f419061e856dfa
              mime_part_count: 2
  mail_extension_header_value: X-Received - by 10.221.47.193 with SMTP id ut1mr14470624vcb.8.1384763184960;
 Mon, 18 Nov 2013 00:26:24 -0800 (PST)
                               X-Proofpoint-Spam-Details - rule=notspam policy=default score=0 spamscore=0
 suspectscore=0 phishscore=0 bulkscore=0 adultscore=0 classifier=scan_limit
 adjust=0 reason=mlx scancount=1 engine=7.0.1-1308280000
 definitions=main-1311180004
                               X-Proofpoint-Virus-Version - vendor=fsecure
 engine=2.50.10432:5.10.8794,1.0.14,0.0.0000
 definitions=2013-11-18_02:2013-11-18,2013-11-17,1970-01-01 signatures=0
                    mail_date: 2013-11-18 08:26:24

Feature key:
  mail_address:  Parsed email addresses from headers
  mail_cc:  Copy addresses from mail headers
  mail_date:  Time the email was sent in UTC
  mail_domain:  Domain names from any associated email addresses
  mail_extension_header:  Mail header extension field
  mail_extension_header_value:  Value of header extension field
  mail_from:  Origin address from message headers
  mail_message_id:  Unique ID assigned to the mail message
  mail_subject:  Message subject line
  mail_timezone:  Local timezone offset the email was sent from
  mail_to:  Recipient addresses from mail headers
  mime_part_count:  Count of any MIME objects within binary
  mime_part_hash:  SHA256 of any decoded MIME objects within binary

Generated child entities (2):
  {'action': 'extracted'} <binary: 6f36cb718943751db9dc4c9df624c4390d8a13674127b7e919f419061e856dfa>
    content: 969674 bytes
  {'action': 'extracted'} <binary: 3b43fdeca80da38c80e918e8f21cbd6fc925dac994f3922c7893fc6c1326fb92>
    content: 1033142 bytes
```

Automated usage in system:

```
azul-plugin-olemail --server http://azul-dispatcher.localnet/
```

## Usage: azul-mail-headers

Parses common RFC 2822 email headers as features such as From and To
address details, subject lines and extension headers.

Usage on local files:

```
azul-plugin-mail-headers test.eml
```

Example Output:

```
----- MailHeaders results -----
OK

Output features:
                  mail_domain: online-convert.com
                   mail_agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:38.0) Gecko/20100101
 Thunderbird/38.5.1
  mail_extension_header_value: X-bounce-key - webpack.hosteurope.de;time2talk@online-convert.com;1455693085;1ff5b968;
                      mail_to: Online-Convert.com <time2help@online-convert.com>
                    mail_from: Online-Convert.com <time2talk@online-convert.com>
                 mail_subject:  EML Example File
                    mail_date: 2016-02-17 07:11:20
                 mail_address: time2help@online-convert.com
                               time2talk@online-convert.com
        mail_extension_header: X-bounce-key
                mail_timezone: +0100
              mail_message_id: <56C41D18.3060102@online-convert.com>

Feature key:
  mail_address:  Parsed email addresses from headers
  mail_agent:  Mail client that sent message
  mail_date:  Time the email was sent in UTC
  mail_domain:  Domain names from any associated email addresses
  mail_extension_header:  Mail header extension field
  mail_extension_header_value:  Value of header extension field
  mail_from:  Origin address from message headers
  mail_message_id:  Unique ID assigned to the mail message
  mail_subject:  Message subject line
  mail_timezone:  Local timezone offset the email was sent from
  mail_to:  Recipient addresses from mail headers
```

Automated usage in system:

```
azul-plugin-mail-headers --server http://azul-dispatcher.localnet/
```

## Usage: azul-mime-decoder

Decodes MIME encoded content in arbitrary files types, including RFC 2822 mail.
Extracted content is raised as children.

Usage on local files:

```
azul-plugin-mime-decoder test.eml
```

Example Output:

```
----- MimeDecoder results -----
OK

Output features:
  mime_part_count: 2
   mime_part_type: application/octet-stream
                   text/html
     mime_version: 1.0
    mime_boundary: ----=_20200331174442000000_99914
   mime_part_hash: 0cf83c15ec9d9af82017435517b91c09aa219b37f1ad0c467b673cb3436033fa
                   635686d3757de56c0b4f4fcdfb9cebb1df00e984f1c1bc37a964d90b877f1ead

Feature key:
  mime_boundary:  The boundary marker used in the MIME document
  mime_part_count:  Count of any MIME objects within binary
  mime_part_hash:  SHA256 of any decoded MIME objects within binary
  mime_part_type:  Content types of objects contained in this MIME document
  mime_version:  The MIME version of the document

Generated child entities (1):
  {'action': 'extracted', 'encoding': 'base64'} <binary: 0cf83c15ec9d9af82017435517b91c09aa219b37f1ad0c467b673cb3436033fa>
    content: 365056 bytes
```

Automated usage in system:

```
azul-plugin-mime-decoder --server http://azul-dispatcher.localnet/
```

## Usage email-parser

Parsing email content:

```bash
email-parser strangeDate.msg
```

output:

```
Filename: strangeDate.msg
--------------------------------------------------------------------------------
Date: Tue, 23 Feb 2016 14:57:50 +0000
From: None
To: time2talk@online-convert.com
Cc:
Subject: MSG Test File
Attachments: []
Body:
MSG test file
Purpose: Provide example of this file type
Document file type: MSG
Version: 1.0
Remark:

Example content:
The names "John Doe" for males, "Jane Doe" or "Jane Roe" for females,
or "Jonnie Doe" and "Janie Doe" for children, or just "Doe"
non-gender-specifically are used as placeholder names for a party whose
true identity is unknown or must be withheld in a legal action, case, or
discussion. The names are also used to refer to a corpse or hospital
patient whose identity is unknown. This practice is widely used in the
United States and Canada, but is rarely used in other English-speaking
countries including the United Kingdom itself, from where the use of
"John Doe" in a legal context originates. The names Joe Bloggs or John
Smith are used in the UK instead, as well as in Australia and New
Zealand.

John Doe is sometimes used to refer to a typical male in other contexts
as well, in a similar manner to John Q. Public, known in Great Britain
as Joe Public, John Smith or Joe Bloggs. For example, the first name
listed on a form is often John Doe, along with a fictional address or
other fictional information to provide an example of how to fill in the
form. The name is also used frequently in popular culture, for example
in the Frank Capra film Meet John Doe. John Doe was also the name of a
2002 American television series.

Similarly, a child or baby whose identity is unknown may be referred to
as Baby Doe. A notorious murder case in Kansas City, Missouri, referred
to the baby victim as Precious Doe. Other unidentified female murder
victims are Cali Doe and Princess Doe. Additional persons may be called
James Doe, Judy Doe, etc. However, to avoid possible confusion, if two
anonymous or unknown parties are cited in a specific case or action, the
surnames Doe and Roe may be used simultaneously; for example, "John Doe
v. Jane Roe". If several anonymous parties are referenced, they may
simply be labelled John Doe #1, John Doe #2, etc. (the U.S. Operation
Delego cited 21 (numbered) "John Doe"s) or labelled with other variants
of Doe / Roe / Poe / etc. Other early alternatives such as John Stiles
and Richard Miles are now rarely used, and Mary Major has been used in
some American federal cases.

File created by http://www.online-convert.com
<http://www.online-convert.com>
More example files: http://www.online-convert.com/file-type
<http://www.online-convert.com/file-type>
Text of Example content: Wikipedia
<http://en.wikipedia.org/wiki/John_Doe>
License: Attribution-ShareAlike 3.0 Unported
<http://creativecommons.org/licenses/by-sa/3.0/>

Feel free to use and share the file according to the license above.

--------------------------------------------------------------------------------
```

## Python Package management

This python package is managed using a `setup.py` and `pyproject.toml` file.

Standardisation of installing and testing the python package is handled through tox.
Tox commands include:

```bash
# Run all standard tox actions
tox
# Run linting only
tox -e style
# Run tests only
tox -e test
```

## Dependency management

Dependencies are managed in the requirements.txt, requirements_test.txt and debian.txt file.

The requirements files are the python package dependencies for normal use and specific ones for tests
(e.g pytest, black, flake8 are test only dependencies).

The debian.txt file manages the debian dependencies that need to be installed on development systems and docker images.

Sometimes the debian.txt file is insufficient and in this case the Dockerfile may need to be modified directly to
install complex dependencies.
