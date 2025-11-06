"""OLE2 Email Parser.

This plugin parser OLE2 email files (Microsoft Outlook .msg) to
feature common mail headers and raise any attachments as child entities.

The textual body content is also published as a data stream for display.
"""

from hashlib import sha256

from azul_runner import DataLabel, Feature, FeatureType, Job, add_settings, cmdline_run

from azul_plugin_email.parser import Message

from .helpers import get_words
from .template import AzulPluginMailParser


class AzulPluginOleMail(AzulPluginMailParser):
    """Outlook email parsing plugin."""

    VERSION = "2025.03.18"
    SETTINGS = add_settings(filter_data_types={"content": ["document/office/ole"]})
    FEATURES = {
        Feature(name="mime_part_count", desc="Count of any MIME objects within binary", type=FeatureType.Integer),
        Feature(
            name="mime_part_hash", desc="SHA256 of any decoded MIME objects within binary", type=FeatureType.String
        ),
        Feature(
            name="processing_failure",
            desc="Plugin is not able to handle the requested binary",
            type=FeatureType.String,
        ),
        Feature(name="filename", desc="Attachment filename extracted from email", type=FeatureType.Filepath),
    }
    filter_require_data = True

    def execute(self, job: Job):
        """Process any OLE2 email messages (Outlook filetype).

        Extracts attachment as children and features corresponding mail headers.
        """
        path = job.get_data().get_filepath()
        features = {}
        try:
            msg = Message(path)
        except OSError as ex:
            features["processing_failure"] = "Unable to parse OLE file: %s" % str(ex)
            self.add_many_feature_values(features)
            return

        # nothing parsed
        if not msg or not msg.body:
            return

        # handled by template
        if msg.header:
            features = self.parse_headers(msg.header)

        # there may be cases where the mime headers fail to parse from
        # the .msg but the basic fields can still be extracted from the
        # specific ole2 stream equivalents
        if not features.get("mail_from") and msg.sender:
            features["mail_from"] = msg.sender
        if not features.get("mail_subject") and msg.subject:
            features["mail_subject"] = msg.subject
        if not features.get("mail_to") and msg.to:
            features["mail_to"] = msg.to
        if not features.get("mail_cc") and msg.cc:
            features["mail_cc"] = msg.cc
        if not features.get("mail_date") and msg.date:
            features.update(self.parse_date(msg.date))

        # reuse the mime decoders child features as the .msg is really just
        # derived from a mime encoded mail anyway..although we only include
        # attachments not any mime parts that were used as the email body.
        hashes = set()
        count = 0
        # extract any attachments as child entities
        for x in msg.attachments:
            if not x.data:
                continue

            filename = x.long_filename or x.short_filename
            c = self.add_child_with_data({"action": "extracted"}, x.data)  # might be a password protected attachment
            # supply the mail body text for any unboxing attempts
            if msg.body:
                c.add_data(DataLabel.PASSWORD_DICTIONARY, {}, get_words([msg.body.encode("utf-8")], filename))
            c.add_feature_values("filename", filename)
            h = sha256()
            h.update(x.data)
            hashes.add(h.hexdigest())
            count = count + 1

        if count:
            features["mime_part_count"] = count
            features["mime_part_hash"] = list(hashes)

        # raise body as txt report
        self.add_data(DataLabel.TEXT, {}, msg.body.encode("utf-8"))
        self.add_many_feature_values(features)


def main():
    """Run plugin from the command-line."""
    cmdline_run(plugin=AzulPluginOleMail)


if __name__ == "__main__":
    main()
