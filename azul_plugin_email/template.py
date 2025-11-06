"""This module defines the template for EMail parsing plugins."""

import email
import re
import time
from datetime import datetime
from email import header

from azul_runner import BinaryPlugin, Feature, FeatureType, FeatureValue, Uri


class AzulPluginMailParser(BinaryPlugin):
    """Generic Azul mail plugin template.

    Handles conversion from RFC2822 mail headers to Azul features for
    any plugin that can produce/extract them.
    """

    FEATURES = [
        Feature(name="mail_from", desc="Origin address from mail or envelope headers", type=FeatureType.String),
        Feature(name="mail_to", desc="Recipient addresses from mail or envelope headers", type=FeatureType.String),
        Feature(name="mail_cc", desc="Copy addresses from mail headers", type=FeatureType.String),
        Feature(name="mail_bcc", desc="Blind copy addresses from mail headers", type=FeatureType.String),
        Feature(name="mail_subject", desc="Message subject line", type=FeatureType.String),
        Feature(name="mail_message_id", desc="Unique ID assigned to the mail message", type=FeatureType.String),
        Feature(name="mail_date", desc="Time the email was sent in UTC", type=FeatureType.Datetime),
        Feature(name="mail_timezone", desc="Local timezone offset the email was sent from", type=FeatureType.String),
        Feature(name="mail_return_path", desc="Return address from mail headers", type=FeatureType.String),
        Feature(name="mail_address", desc="Parsed email addresses from headers", type=FeatureType.String),
        Feature(name="mail_domain", desc="Domain names from any associated email addresses", type=FeatureType.Uri),
        Feature(name="mail_agent", desc="Mail client that sent message", type=FeatureType.String),
        Feature(name="mail_extension_header", desc="Mail header extension field", type=FeatureType.String),
        Feature(name="mail_extension_header_value", desc="Value of header extension field", type=FeatureType.String),
    ]

    def parse_date(self, dstring):
        """Given an email timestamp str, convert to a datetime object."""
        features = {}
        # extract the timezone offset as we are going to lose it in normalising to UTC
        m = re.search(r"([\+\-]\d{4}$|[A-Z]{3}$)", dstring)
        if m:
            features["mail_timezone"] = m.group(1)

        st = email.utils.parsedate_tz(dstring)
        if st:
            dt = datetime.fromtimestamp(time.mktime(st[0:-1]) - st[-1])
            features["mail_date"] = dt
        return features

    def parse_headers(self, msg):
        """Parse the email headers from an email message and return as features."""
        # sanity check
        if not msg.get("From"):
            return {}

        features = {}
        # 1:1 mapped features
        if "Message-ID" in msg:
            features["mail_message_id"] = self.get_header("Message-ID", msg)
        if "Subject" in msg:
            features["mail_subject"] = self.get_header("Subject", msg)
        if "X-Mailer" in msg:
            features["mail_agent"] = self.get_header("X-Mailer", msg)
        if "User-Agent" in msg:
            features["mail_agent"] = self.get_header("User-Agent", msg)

        # date conversion
        if msg.get("Date"):
            features.update(self.parse_date(msg["Date"]))
        # X mail headers
        for k, v in msg.items():
            if k.startswith("X-"):
                val = self.decode_mime_encoded_word(v)
                features.setdefault("mail_extension_header", []).append(k)
                features.setdefault("mail_extension_header_value", []).append(FeatureValue(val, label=k))

        # any email address fields
        for hdr, feat in [
            ("From", "mail_from"),
            ("To", "mail_to"),
            ("Cc", "mail_cc"),
            ("Bcc", "mail_bcc"),
            ("Return-Path", "mail_return_path"),
            ("X-Rcpt-To", "mail_to"),
            ("X-Envelope-To", "mail_to"),
            ("X-Envelope-From", "mail_from"),
        ]:
            raw = msg.get(hdr)
            if not raw:
                continue

            # unescape and decode
            raw = self.decode_mime_encoded_word(raw)
            raw = raw.replace("\\(", "(")
            raw = raw.replace("\\)", ")")

            # split into list of address fields
            for x in re.findall(r"\".+?\"", raw):
                raw = raw.replace(x, x.replace(";", "\x01"))
                raw = raw.replace(x, x.replace(",", "\x02"))
            # seems we can see ',' ';' and sometimes both used as separators
            raw = raw.replace(",", ";")  # reduce to one sep
            raw = raw.split(";")

            # raise as features
            for x in raw:
                # undo the above quoted value hack
                x = x.replace("\x01", ";")
                x = x.replace("\x02", ",")
                feat_value = x.strip()
                if feat_value:
                    features.setdefault(feat, []).append(feat_value)

            # address extraction
            for _, addr in email.utils.getaddresses(raw):
                # sanity check that it looks like an email address
                if "@" not in addr:
                    continue
                dom = addr.split("@")[1]
                features.setdefault("mail_address", []).append(addr)
                features.setdefault("mail_domain", []).append(Uri(dom))

        return features

    def decode_mime_encoded_word(self, encoded):
        """Decode mime encoded word fields.

        Tries to decode any strings with mime encoded words as done to
        escape foreign charsets in mail header values.

        Handles non encoded strings safely.
        """
        try:
            decoded = header.decode_header(encoded)
            return "".join([s.decode(t or "ascii") for s, t in decoded])
        except Exception:
            return encoded

    def get_header(self, propname, propdict):
        """Decode and return the specified header field as a unicode str."""
        if propname in propdict:
            val = propdict[propname]
            return self.decode_mime_encoded_word(val)
        return None
