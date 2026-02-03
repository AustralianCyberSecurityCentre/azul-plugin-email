"""Ole2 Email (Outlook) Parsing.

Most of the following taken from https://github.com/mattgwwalker/msg-extractor
Copyright 2013 Matthew Walker

Note: the above GPLv3 project has evolved a lot over the last 7 years and is
now a proper python package.  We should look to deprecate olemail in favour
of using that tool directly, in downstream projects, in the future.
"""

import email.utils
import logging
import os
import random
import re
import string
import struct
import sys
from datetime import UTC, datetime
from email.parser import Parser as EmailParser

import click
import olefile

logger = logging.getLogger(__name__)

# Epoch Jan 1, 1601 in 100ns units
EPOCH_1601 = 116444736000000000

# This property information was sourced from
# http://www.fileformat.info/format/outlookmsg/index.htm
# on 2013-07-22.
properties = {
    "001A": "Message class",
    "0037": "Subject",
    "003D": "Subject prefix",
    "0040": "Received by name",
    "0042": "Sent repr name",
    "0044": "Rcvd repr name",
    "004D": "Org author name",
    "0050": "Reply rcipnt names",
    "005A": "Org sender name",
    "0064": "Sent repr adrtype",
    "0065": "Sent repr email",
    "0070": "Topic",
    "0075": "Rcvd by adrtype",
    "0076": "Rcvd by email",
    "0077": "Repr adrtype",
    "0078": "Repr email",
    "007d": "Message header",
    "0C1A": "Sender name",
    "0C1E": "Sender adr type",
    "0C1F": "Sender email",
    "0E02": "Display BCC",
    "0E03": "Display CC",
    "0E04": "Display To",
    "0E1D": "Subject (normalized)",
    "0E28": "Recvd account1 (uncertain)",
    "0E29": "Recvd account2 (uncertain)",
    "1000": "Message body",
    "1008": "RTF sync body tag",
    "1035": "Message ID (uncertain)",
    "1046": "Sender email (uncertain)",
    "3001": "Display name",
    "3002": "Address type",
    "3003": "Email address",
    "39FE": "7-bit email (uncertain)",
    "39FF": "7-bit display name",
    # Attachments (37xx)
    "3701": "Attachment data",
    "3703": "Attachment extension",
    "3704": "Attachment short filename",
    "3707": "Attachment long filename",
    "370E": "Attachment mime tag",
    "3712": "Attachment ID (uncertain)",
    # Address book (3Axx):
    "3A00": "Account",
    "3A02": "Callback phone no",
    "3A05": "Generation",
    "3A06": "Given name",
    "3A08": "Business phone",
    "3A09": "Home phone",
    "3A0A": "Initials",
    "3A0B": "Keyword",
    "3A0C": "Language",
    "3A0D": "Location",
    "3A11": "Surname",
    "3A15": "Postal address",
    "3A16": "Company name",
    "3A17": "Title",
    "3A18": "Department",
    "3A19": "Office location",
    "3A1A": "Primary phone",
    "3A1B": "Business phone 2",
    "3A1C": "Mobile phone",
    "3A1D": "Radio phone no",
    "3A1E": "Car phone no",
    "3A1F": "Other phone",
    "3A20": "Transmit dispname",
    "3A21": "Pager",
    "3A22": "User certificate",
    "3A23": "Primary Fax",
    "3A24": "Business Fax",
    "3A25": "Home Fax",
    "3A26": "Country",
    "3A27": "Locality",
    "3A28": "State/Province",
    "3A29": "Street address",
    "3A2A": "Postal Code",
    "3A2B": "Post Office Box",
    "3A2C": "Telex",
    "3A2D": "ISDN",
    "3A2E": "Assistant phone",
    "3A2F": "Home phone 2",
    "3A30": "Assistant",
    "3A44": "Middle name",
    "3A45": "Dispname prefix",
    "3A46": "Profession",
    "3A48": "Spouse name",
    "3A4B": "TTYTTD radio phone",
    "3A4C": "FTP site",
    "3A4E": "Manager name",
    "3A4F": "Nickname",
    "3A51": "Business homepage",
    "3A57": "Company main phone",
    "3A58": "Childrens names",
    "3A59": "Home City",
    "3A5A": "Home Country",
    "3A5B": "Home Postal Code",
    "3A5C": "Home State/Provnce",
    "3A5D": "Home Street",
    "3A5F": "Other adr City",
    "3A60": "Other adr Country",
    "3A61": "Other adr PostCode",
    "3A62": "Other adr Province",
    "3A63": "Other adr Street",
    "3A64": "Other adr PO box",
    "3FF7": "Server (uncertain)",
    "3FF8": "Creator1 (uncertain)",
    "3FFA": "Creator2 (uncertain)",
    "3FFC": "To email (uncertain)",
    "403D": "To adrtype (uncertain)",
    "403E": "To email (uncertain)",
    "5FF6": "To (uncertain)",
}


def windows_unicode(string):
    """Convert UTF-16 encoded byte string to python string."""
    if string is None:
        return None
    # Python 3+
    if sys.version_info[0] >= 3:
        return str(string, "utf_16_le")
    # Python 2
    return unicode(string, "utf_16_le")  # noqa: F821


class Attachment:
    """Extractor for outlook attachment streams."""

    def __init__(self, msg, dir_):
        """Wrap a stream to extract the file attachment."""
        # Get long filename
        self.long_filename = msg._get_string_stream([dir_, "__substg1.0_3707"])

        # Get short filename
        self.short_filename = msg._get_string_stream([dir_, "__substg1.0_3704"])

        # Get attachment data
        self.data = msg._get_stream([dir_, "__substg1.0_37010102"])

    def save(self, outpath):
        """Write the attachment out to the filesystem path."""
        # Use long filename as first preference
        filename = self.long_filename
        # Otherwise use the short filename
        if filename is None:
            filename = self.short_filename
        # Otherwise just make something up!
        if filename is None:
            r = "".join(
                random.choice(string.ascii_uppercase + string.digits)  # noqa: S311
                for _ in range(5)
            )
            filename = "UnknownFilename " + r + ".bin"
        # ensure there's no shenanigans with path chars
        filename = os.basename(filename)
        with open(os.path.join(outpath, filename), "wb") as f:
            f.write(self.data)
            return f.name


class Message(olefile.OleFileIO):
    """Outlook message parser."""

    def __init__(self, filename):
        """Load and parse the email at the specified file location."""
        olefile.OleFileIO.__init__(self, filename)

    def _get_stream(self, filename) -> bytes | None:
        if self.exists(filename):
            stream = self.openstream(filename)
            return stream.read()
        else:
            return None

    def _get_string_stream(self, filename, prefer="unicode") -> str | None:
        """Get the string representation of the requested filename.

        Checks for both ASCII and Unicode representations and returns
        a value if possible.  If there are both ASCII and Unicode
        versions, then the parameter /prefer/ specifies which will be
        returned.
        """
        if isinstance(filename, list):
            # Join with slashes to make it easier to append the type
            filename = "/".join(filename)

        ascii_string = self._get_stream(filename + "001E")
        decoded_ascii = None
        try:
            decoded_ascii = ascii_string.decode(encoding="iso-8859-1")
        except Exception:
            logger.info("ASCII decoding failed, either unicode will be used or the email can't be decoded.")
        unicode_string = windows_unicode(self._get_stream(filename + "001F"))
        if ascii_string is None:
            return unicode_string
        elif unicode_string is None:
            return decoded_ascii
        else:
            if prefer == "unicode":
                return unicode_string
            else:
                return decoded_ascii

    @property
    def subject(self):
        """Return the message subject line."""
        return self._get_string_stream("__substg1.0_0037")

    @property
    def header(self):
        """Return any enclosed MIME email headers."""
        try:
            return self._header
        except Exception:
            header_text = self._get_string_stream("__substg1.0_007D")
            if header_text:
                # strip to first rfc header as outlook can add its own
                # premable which breaks parsing
                header_lines = header_text.splitlines()
                i = 0
                for line in header_lines:
                    if re.match(r"\w{2,}: [\w\d]", line):
                        break
                    i += 1
                header_text = "\r\n".join(header_lines[i:])
                self._header = EmailParser().parsestr(header_text)
            else:
                self._header = None
            return self._header

    @property
    def date(self):
        """Return the message sent timestamp."""
        # Get the message's header and extract the date
        if self.header is None:
            # in some cases we can still derive from properties stream
            props = self._get_props()
            ts = props.get(0x40)
            if not ts:
                return None
            d = datetime.fromtimestamp((struct.unpack("<Q", ts)[0] - EPOCH_1601) / 10000000.0, UTC)
            return d.strftime("%a, %d %b %Y %H:%M:%S +0000")
        return self.header["date"]

    def _get_props(self):
        """Parse and return the properties stream items.

        This is a very incomplete parse of the properties stream format.
        It is only currently used to extract date information.
        """
        p = self._get_stream("__properties_version1.0")
        if not p:
            return {}
        # need to trim prefix and split into 16 byte properties (does not handle variable types)
        p = p[len(p) % 16 :]
        pl = [p[i : i + 16] for i in range(0, len(p), 16)]
        # creating mapping from type id's to raw values
        pd = dict([struct.unpack("<H6x8s", x) for x in pl])
        return pd

    @property
    def parsed_date(self):
        """Return the message time as a datetime."""
        return email.utils.parsedate(self.date)

    @property
    def sender(self):
        """Return the email sender address."""
        try:
            return self._sender
        except Exception:
            # Check header first
            if self.header is not None:
                header_result = self.header["from"]
                if header_result is not None:
                    self._sender = header_result
                    return header_result

            # Extract from other fields
            text = self._get_string_stream("__substg1.0_0C1A")
            email = self._get_string_stream("__substg1.0_0C1F")
            result = None
            if text is None:
                result = email
            else:
                result = text
                if email is not None:
                    result = result + " <" + email + ">"

            self._sender = result
            return result

    @property
    def to(self):
        """Return the email recipient addresses."""
        try:
            return self._to
        except Exception:
            # Check header first
            if self.header is not None:
                header_result = self.header["to"]
                if header_result is not None:
                    self._to = header_result
                    return header_result

            # Extract from other fields
            # FUTURE: This could be  extracted from the recip folders.
            display = self._get_string_stream("__substg1.0_0E04")
            display = display.rstrip("\0")
            self._to = display
            return display

    @property
    def cc(self):
        """Return any carbon copy addresses."""
        try:
            return self._cc
        except Exception:
            # Check header first
            if self.header is not None:
                header_result = self.header["cc"]
                if header_result is not None:
                    self._cc = header_result
                    return header_result

            # Extract from other fields
            # FUTURE: This could be  extracted from the recip folders.
            display = self._get_string_stream("__substg1.0_0E03")
            display = display.rstrip("\0")
            self._cc = display
            return display

    @property
    def body(self):
        """Return the Message body stream."""
        return self._get_string_stream("__substg1.0_1000")

    @property
    def attachments(self):
        """Return a list of any attachments."""
        try:
            return self._attachments
        except Exception:
            # Get the attachments
            attachment_dirs = []

            for dir_ in self.listdir():
                if dir_[0].startswith("__attach") and dir_[0] not in attachment_dirs:
                    attachment_dirs.append(dir_[0])

            self._attachments = []

            for attachment_dir in attachment_dirs:
                self._attachments.append(Attachment(self, attachment_dir))

            return self._attachments

    def dump(self):
        """Print information about the parsed contents."""
        # Prints out a summary of the message
        print("Date: %s" % self.date)
        print("From: %s" % self.sender)
        print("To: %s" % self.to)
        print("Cc: %s" % self.cc)
        print("Subject: %s" % self.subject)
        print("Attachments: [%s]" % ", ".join([x.long_filename for x in self.attachments]))
        print("Body:")
        print(self.body)

    def debug(self):
        """Print debugging information about the message ole streams."""
        for dir_ in self.listdir():
            if dir_[-1].endswith("001E", "001F"):
                print("Directory: " + str(dir_))
                print("Contents: " + self._get_stream(dir_))


@click.command()
@click.argument("filename", nargs=-1)
def main(filename: tuple[str]):
    """Parse and print the email details for the supplied outlook files."""
    for f in filename:
        print("Filename: %s" % f)
        print("-" * 80)
        try:
            m = Message(f)
            m.dump()
        except OSError as ex:
            print("Unable to parse: %s" % str(ex))
        print("-" * 80)
