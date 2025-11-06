"""RFC822 Mail Headers Parser.

This plugin parses standard RFC822 mail headers (RFC2822), as seen
in raw SMTP transports.

Extraction of mime encoded attachments should be handled by the
*mime_decoder* plugin, so is not reproduced here.

"""

import email
import re

from azul_runner import Job, State, add_settings, cmdline_run

from .template import AzulPluginMailParser


class AzulPluginMailHeaders(AzulPluginMailParser):
    """Email header parsing plugin."""

    VERSION = "2025.03.18"
    SETTINGS = add_settings(filter_data_types={"content": ["document/email", "document/office/email", "text/plain"]})
    FEATURES = AzulPluginMailParser.FEATURES

    def execute(self, job: Job):
        """Extract any mail headers from appropriate file types, or optout."""
        # Handle parsing files identified as email but have some
        # preamble prefixed to the content of the raw mail message.
        header = job.get_data().read(2048)
        m = re.search(rb'\w{3,}: ["\w\d=]', header)
        if not m:
            # Nothing that looks like a mail header was found
            return State.Label.OPT_OUT

        path = job.get_data().get_filepath()
        try:
            with open(path, "rb") as f:
                f.seek(m.start())
                msg = email.message_from_binary_file(f)
        except UnicodeDecodeError:
            # probably not real email
            return State.Label.OPT_OUT

        self.add_many_feature_values(self.parse_headers(msg))


def main():
    """Run plugin from command-line."""
    cmdline_run(plugin=AzulPluginMailHeaders)


if __name__ == "__main__":
    main()
