"""MIME Decoder Plugin.

This plugin will extract parts of a mime based document (e.g. an email in plain
text). Relationships are "mime_decoder extracts <content_type>".
"""

import os
import re
from email import generator, header, message
from email.parser import BytesParser
from hashlib import sha256
from io import StringIO

from azul_runner import (
    BinaryPlugin,
    DataLabel,
    Feature,
    FeatureType,
    Filepath,
    Job,
    State,
    Uri,
    add_settings,
    cmdline_run,
)
from bs4 import BeautifulSoup

from .helpers import get_words

# sometimes mime parts have wrong mime types, so check content too
POSSIBLE_ENCRYPTED_MAGICS = (
    b"PK",
    b"\xd0\xcf\x11",
    b"Rar!",
    b"%PDF",
    b"7z",
)
HEADER_PATTERN = re.compile(rb"^([-\w]+): ([^\r\n;])", re.M)
SCAN_DEPTH = 5000


class AzulPluginMimeDecoder(BinaryPlugin):
    """Decodes mime encoded attachments from emails and documents."""

    VERSION = "2025.03.18"
    SETTINGS = add_settings(
        filter_data_types={
            "content": [
                "document/",
                "image/",
                "video/",
                "audio/",
                "code/html",
                "code/xml",
                "javascript",
                "resource/mo",  # .mo (machine object files) used in software localization. Can contain mime headers.
                "text/plain",
                "text/json",
            ]
        },
        # decoded content-types to ignore as children
        content_type_filter=(
            list[str],
            [
                "text/plain",
                "text/html",
                "text/xml",
                "text/css",
                "text/javascript",
                "application/javascript",
                "application/x-javascript",
                "message/delivery-status",
            ],
        ),
        # publish plain text stream of any mail body
        report_mail_bodies=(bool, True),
        # publish remaining data after last boundary as child
        appended_data_as_child=(bool, False),
    )
    FEATURES = [
        Feature(name="mime_version", desc="The MIME version of the document", type=FeatureType.String),
        Feature(name="mime_boundary", desc="The boundary marker used in the MIME document", type=FeatureType.String),
        Feature(name="mime_part_count", desc="Count of any MIME objects within binary", type=FeatureType.Integer),
        Feature(
            name="mime_part_hash", desc="SHA256 of any decoded MIME objects within binary", type=FeatureType.String
        ),
        Feature(
            name="mime_part_type",
            desc="Content types of objects contained in this MIME document",
            type=FeatureType.String,
        ),
        Feature(
            name="mime_content_type",
            desc="Content type of the object extract from a MIME document",
            type=FeatureType.String,
        ),
        Feature(
            name="mime_content_encoding",
            desc="Content encoding of object extracted from a MIME document",
            type=FeatureType.String,
        ),
        Feature(
            name="mime_content_location",
            desc="Content location of object extracted from a MIME document",
            type=FeatureType.Uri,
        ),
        Feature(
            name="mime_content_id", desc="Content Id of object extracted from a MIME document", type=FeatureType.String
        ),
        Feature(
            name="processing_failure",
            desc="Plugin is not able to handle the requested binary",
            type=FeatureType.String,
        ),
        Feature(name="filename", desc="Attachment filename extracted from email", type=FeatureType.Filepath),
        Feature(name="tag", desc="An informational label about the binary", type=FeatureType.String),
    ]

    def execute(self, job: Job):
        """Run on most files, but opt out if can't find or parse MIME headers in beginning of file."""
        data = job.get_data()
        buf = data.read(SCAN_DEPTH)
        m = HEADER_PATTERN.search(buf)
        if not m:
            return State(
                State.Label.OPT_OUT, message=f"No match found in header for pattern: {HEADER_PATTERN.pattern}"
            )

        # strip any preamble and read rest of content
        # email library seems to drop carriage returnes if read from file, so we read from byte string
        data.seek(m.start())
        buf = data.read()

        parser = BytesParser()
        msg = parser.parsebytes(buf)

        # need at least mime-version field to be set
        if "mime-version" not in [x.lower() for x in msg.keys()]:
            return State(State.Label.OPT_OUT, message="mime-version not found in parsed keys.")

        # examine the parts in the list
        features = self.walk_message(msg)

        if msg.epilogue and msg.epilogue.strip():
            features["tag"] = "trailing_data"
            # raise as child entity
            if self.cfg.appended_data_as_child:
                self.add_child_with_data(
                    relationship={"action": "extracted", "type": "epilogue"},
                    data=msg.epilogue.encode(),
                )
        self.add_many_feature_values(features)

    def walk_message(self, msg: message.Message):
        """Walk the mime objects in the supplied email.Message raising relevant children and features."""
        # set some top-level features
        features = {"mime_version": {k.lower(): v for k, v in msg.raw_items()}.get("mime-version")}

        if msg.get_boundary():
            features["mime_boundary"] = msg.get_boundary()

        content_types = set()
        section_hashes = set()
        count = 0
        plain_text = []
        html_text = []
        for part in msg.walk():
            # ignore multipart as we'll get the subparts anyway
            if part.get_content_maintype() == "multipart":
                continue

            # include in count even if filtered later
            count += 1
            child_features = dict()

            # extract content out of the mime header
            content_type = part.get_content_type()
            content_encoding = dict(part.items()).get("Content-Transfer-Encoding")
            content_filename = part.get_filename() or os.path.basename(part.get("Content-Location", ""))

            # handle mime encoded-word filenames
            try:
                decoded = header.decode_header(content_filename)
                content_filename = "".join([s.decode(t or "ascii") for s, t in decoded])
            except Exception:  # noqa: S110 # noqa: S110
                # just use the raw string if it doesn't decode
                pass

            # add these before filtering
            content_types.add(content_type)

            # decode the part if its encoded
            if not content_encoding:
                decoded_part = part.get_payload()
                content_encoding = "none"
            else:
                decoded_part = part.get_payload(decode=True)
                child_features["mime_content_encoding"] = content_encoding

            # if the major content type is "message", get_payload() will return a list
            if type(decoded_part) is list:
                fp = StringIO()
                g = generator.Generator(fp, mangle_from_=False, maxheaderlen=600)
                g.flatten(part)
                decoded_part = fp.getvalue()

            if type(decoded_part) is str:
                decoded_part = decoded_part.encode("utf-8")

            # a decoded part length of zero is something we can ignore
            if not decoded_part:
                continue

            # hash the section
            h = sha256()
            h.update(decoded_part)
            section_hashes.add(h.hexdigest())

            # no filename and is text/plain is most likely mail body text
            # raise as txt report so it gets indexed/etc.
            if self.cfg.report_mail_bodies and not content_filename and content_type == "text/plain":
                # we don't want to publish just whitespace
                if decoded_part.strip():
                    plain_text.append(decoded_part)

            if self.cfg.report_mail_bodies and not content_filename and content_type == "text/html":
                # some mail will only contain html body
                soup = BeautifulSoup(decoded_part, features="html.parser")
                text = soup.get_text().encode("utf-8")
                if text.strip():
                    html_text.append(text)

            # not interested in items from the defeat list
            if content_type in self.cfg.content_type_filter:
                continue

            # set up a dict for the child features
            child_features["mime_content_type"] = content_type
            if part.get("Content-Location"):
                child_features["mime_content_location"] = Uri(part.get("Content-Location"))
            if part.get("Content-ID"):
                child_features["mime_content_id"] = part.get("Content-ID")

            # set the filename field for the child if it exists
            if content_filename:
                child_features["filename"] = Filepath(content_filename)

            # raise the decoded mime as a child entity
            c = self.add_child_with_data(
                {
                    "action": "extracted",
                    "encoding": content_encoding,
                },
                decoded_part,
            )
            c.add_many_feature_values(child_features)
            # might be a password protected attachment
            # supply the mail body text for any unboxing attempts
            if (content_type.startswith("application") or decoded_part.startswith(POSSIBLE_ENCRYPTED_MAGICS)) and (
                plain_text or html_text
            ):
                c.add_data(DataLabel.PASSWORD_DICTIONARY, {}, get_words(plain_text or html_text, content_filename))

        # choose which text to output, if any
        if plain_text:
            for p in plain_text:
                self.add_data(DataLabel.TEXT, {}, p)
        else:
            for h in html_text:
                self.add_data(DataLabel.TEXT, {}, h)
        if content_types:
            features["mime_part_type"] = list(content_types)
        if section_hashes:
            features["mime_part_hash"] = list(section_hashes)
        features["mime_part_count"] = count
        return features


def main():
    """Run plugin from the command-line."""
    cmdline_run(plugin=AzulPluginMimeDecoder)


if __name__ == "__main__":
    main()
