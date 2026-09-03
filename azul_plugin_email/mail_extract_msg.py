"""Outlook email '.msg' decoder / extractor.

This plugin uses 'extract-msg' https://github.com/TeamMsgExtractor/msg-extractor to
decode and extract content and features from '.msg' files.
"""

from datetime import datetime
from hashlib import sha256

from azul_runner import DataLabel, Feature, FeatureType, Job, State, add_settings, cmdline_run
from extract_msg import openMsg
from extract_msg.attachments.attachment import Attachment
from extract_msg.attachments.attachment_base import AttachmentBase
from extract_msg.attachments.broken_att import BrokenAttachment
from extract_msg.attachments.custom_att import CustomAttachment
from extract_msg.attachments.emb_msg_att import EmbeddedMsgAttachment
from extract_msg.attachments.signed_att import SignedAttachment
from extract_msg.attachments.unsupported_att import UnsupportedAttachment
from extract_msg.attachments.web_att import WebAttachment
from extract_msg.exceptions import UnrecognizedMSGTypeError, UnsupportedMSGTypeError
from extract_msg.msg_classes.appointment import AppointmentMeeting
from extract_msg.msg_classes.calendar import Calendar
from extract_msg.msg_classes.contact import Contact
from extract_msg.msg_classes.journal import Journal
from extract_msg.msg_classes.meeting_cancellation import MeetingCancellation
from extract_msg.msg_classes.meeting_exception import MeetingException
from extract_msg.msg_classes.meeting_forward import MeetingForwardNotification
from extract_msg.msg_classes.meeting_request import MeetingRequest
from extract_msg.msg_classes.meeting_response import MeetingResponse
from extract_msg.msg_classes.message import Message
from extract_msg.msg_classes.message_base import MessageBase
from extract_msg.msg_classes.message_signed import MessageSigned
from extract_msg.msg_classes.post import Post
from extract_msg.msg_classes.sticky_note import StickyNote
from extract_msg.msg_classes.task import Task
from extract_msg.msg_classes.task_request import TaskRequest

from azul_plugin_email.helpers import get_words
from azul_plugin_email.ms_oxprops_enum import MS_OXPROPS
from azul_plugin_email.template import AzulPluginMailParser


class AzulPluginMailExtractMsg(AzulPluginMailParser):
    """The Azul Plugin Mail Extract Msg class.

    Instance that will be created to parse a msg file.
    """

    VERSION = "2026.08.24"
    SETTINGS = add_settings(filter_data_types={"content": ["document/office/ole"]})
    FEATURES = {
        Feature(name="mime_part_count", desc="Count of any MIME objects within binary", type=FeatureType.Integer),
        Feature(
            name="mime_part_type",
            desc="Content types of objects contained in the MIME sections of binary ",
            type=FeatureType.String,
        ),
        Feature(
            name="mime_part_hash", desc="SHA256 of any decoded MIME objects within binary", type=FeatureType.String
        ),
        Feature(
            name="filename",
            desc="Attachment filename extracted from email: if none defaults name to attachment type",
            type=FeatureType.String,
        ),
        Feature(
            name="attachment",
            desc="Type of attachment found in msg: attachment, attachment_embedded, hidden_attachment_web...",
            type=FeatureType.String,
        ),
        Feature(
            name="outlook_type",
            desc="Type of outlook object, e.g. calendar, message, appointment...",
            type=FeatureType.String,
        ),
        Feature(
            name="malformed",
            desc="File is malformed in some way.",
            type=FeatureType.String,
        ),
    }

    def execute(self, job: Job):
        """Extracts attachment as children and features corresponding mail headers."""
        path = job.get_data().get_filepath()
        features: dict[str, str | int | list[str] | datetime] = {}
        try:
            """
            Attempt to open the file. May fail. Lots of arguments to re-attempt with
            """
            msg = openMsg(path, delayAttachments=True)
        except UnsupportedMSGTypeError as ex:
            """
            An exception that is raised when an MSG class is recognized but not
            supported.
            """
            return State(State.Label.COMPLETED_WITH_ERRORS, message="Unsupported MSG type: " + str(ex))
        except UnrecognizedMSGTypeError as ex:
            """
            An exception that is raised when the module cannot determine how to properly
            open a specific class of MSG file.
            """
            return State(State.Label.COMPLETED_WITH_ERRORS, message="Unknown MSG type: " + str(ex))
        except OSError as ex:
            return State(State.Label.COMPLETED_WITH_ERRORS, message="Malformed: " + str(ex))

        # At this point extract_msg should have done all the heavy lifting required
        # Now we just need to map data to features

        # We double check inside function that msg is of MessageBase
        features = self.parse_msg(msg)  # type: ignore

        msg.close()
        self.add_many_feature_values(features)

    def parse_msg(self, msg: MessageBase) -> dict:
        """Takes a msg object and pulls out features we are interested in."""
        features: dict[str, str | int | list[str] | datetime] = {}

        if not issubclass(type(msg), MessageBase):
            self.logger.error("Non-messageBase object given to parse")
            return features

        # Do Generic parsing that works for all .msg files
        if msg.header:
            features = self.parse_headers(msg.header)

        """
        extract_msg internals will currently:
        - msg.body     directly return plaintext body (__substg1.0_1000) if found, or tries to wrap rtfBody
        - msg.htmlBody directly return the HTML stream (__substg1.0_10130102) if found or wrap rtfBody
        - msg.rtfBody  directly return decompressed rtf (__substg1.0_10090102) if found and de-compressible
        """
        extractedBody = None
        if msg.body and type(msg.body) is str:
            extractedBody = msg.body.encode("utf-8")
        elif msg.htmlBody:
            extractedBody = msg.htmlBody
        elif msg.rtfBody:
            extractedBody = msg.rtfBody
        elif msg.compressedRtf:
            # Only hit this case if rtfBody failed to decompress, means malformed
            features["malformed"] = "Unable to decompress RTF email body"
            extractedBody = msg.compressedRtf
        else:
            self.logger.info("Email body does not exist")

        # raise body as txt report
        if extractedBody:
            self.add_data(DataLabel.TEXT, {}, extractedBody)

        # there may be cases where the mime headers fail to parse from
        # the .msg but the basic fields can still be extracted from the
        # specific ole2 stream equivalents
        if not features.get("mail_from") and msg.sender:
            senderEmail, _ = self.textAndEmailSplitter(msg.sender)
            features["mail_from"] = senderEmail
        if not features.get("mail_to") and msg.to:
            toEmail, _ = self.textAndEmailSplitter(msg.to)
            features["mail_to"] = toEmail
        if not features.get("mail_subject") and msg.subject:
            features["mail_subject"] = msg.subject
        if not features.get("mail_cc") and msg.cc:
            features["mail_cc"] = msg.cc
        if not features.get("mail_date"):
            date = None
            if msg.date:
                # msg.date is only populated if message is marked as sent.
                date = msg.date
            else:
                # But dates exist regardless, and could help correlate
                # Check properties for fallback options
                fallback_dates_fields = [
                    MS_OXPROPS.PidTagLastModificationTime,
                    MS_OXPROPS.PidTagCreationTime,
                    MS_OXPROPS.PidTagClientSubmitTime,
                ]
                for field in fallback_dates_fields:
                    value = msg.getPropertyVal(field.value, 0)
                    if value and type(value) is datetime:
                        date = value
                        break
            if date:
                # Have a date:
                # - mail_date: drop microseconds and timezone
                # - mail_timezone: All these fallbacks will return the time in UTC.
                features["mail_date"] = date.replace(microsecond=0, tzinfo=None)
                features["mail_timezone"] = "+0000"
            else:
                self.logger.info("No meaningful date found")

        # do specific message type parsing
        self.parse_msg_particulars(msg, features)

        # extract any attachments as child entities
        self.msg_attachment_extracting(msg.attachments, features, extractedBody)

        return features

    def parse_msg_particulars(self, msg: MessageBase, features: dict):
        """Used to get pull more particular information from a message.

        Data we would feature tag is pulled using general parsing,
        but certain message types may contain some additional information
        that could be helpful.
        """
        match msg:
            case Message():
                # Already fully mapped / extracted
                features["outlook_type"] = "message"
            case AppointmentMeeting():
                # Gets new info such as reoccurrence pattern, start and end date
                self.add_text(msg.getJson())
                features["outlook_type"] = "appointment"
            case Calendar():
                # Do not see evidence of this type being common
                features["outlook_type"] = "calendar"
            case Contact():
                # Large amount of possible additional information
                # checkout extract-msg.msg_classes.contact
                self.add_text(msg.getJson())
                features["outlook_type"] = "contact"
            case Journal():
                # Possible start/end date and companies
                self.add_text(msg.getJson())
                features["outlook_type"] = "journal"
            case MeetingCancellation():
                # important data already extracted
                features["outlook_type"] = "meeting_cancellation"
            case MeetingException():
                # important data already extracted
                features["outlook_type"] = "meeting_exception"
            case MeetingForwardNotification():
                # important data already extracted
                features["outlook_type"] = "meeting_forward_notification"
            case MeetingRequest():
                # important data already extracted
                features["outlook_type"] = "meeting_request"
            case MeetingResponse():
                # important data already extracted
                features["outlook_type"] = "meeting_response"
            case MessageSigned():
                # Not much data seems available
                features["outlook_type"] = "message_signed"
            case Post():
                # Already fully mapped / extracted
                features["outlook_type"] = "post"
            case StickyNote():
                # Only additional info is color and size
                features["outlook_type"] = "sticky_note"
            case TaskRequest():
                # important data already extracted
                features["outlook_type"] = "task_request"
            case Task():
                # important data already extracted
                features["outlook_type"] = "task"

    def msg_attachment_extracting(
        self, attachments: list[AttachmentBase] | list[SignedAttachment], features: dict, messageBody: bytes | None
    ):
        """msg_attachment_extracting.

        Given the attachments for a message, pull out their data and tag them as children of this job.

        @param attachments: Msg attachments object
        @param features: features dict to update
        @param messageBody: Message body to build password dictionaries with
        """
        # reuse the mime decoders child features as the .msg is really just
        # derived from a mime encoded mail anyway. Although we only include
        # attachments not any mime parts that were used as the email body.
        hashes = set()
        mimeType: set[str] = set()
        attachment_types: set[str] = set()
        count = 0

        for attachment in attachments:
            if not attachment.dataType:
                self.logger.info("Either attachment would raise exception or is an empty attachment")
                continue

            extractedData: bytes = b""
            passwordDictionary = None

            # See if lib has a name for the attachment
            filename = attachment.name

            if messageBody:
                if filename:
                    passwordDictionary = get_words([messageBody], filename)
                else:
                    passwordDictionary = get_words([messageBody])

            match attachment:
                case Attachment():
                    type_string = "attachment"
                case BrokenAttachment():
                    type_string = "broken_attachment"
                case CustomAttachment():
                    type_string = "custom_attachment"
                case EmbeddedMsgAttachment():
                    type_string = "embedded_attachment"
                case SignedAttachment():
                    type_string = "signed_attachment"
                case UnsupportedAttachment():
                    type_string = "unsupported_attachment"
                case WebAttachment():
                    type_string = "web_attachment"
                case _:
                    type_string = "unknown_attachment"

            if not isinstance(attachment, SignedAttachment) and attachment.hidden:
                type_string = "hidden_" + type_string

            attachment_types.add(type_string)

            if not filename or filename.rstrip("\x00") == "":
                # Just name the file based on attachment type if empty or only null bytes
                filename = type_string

            # Do actual extraction of attachment data
            if attachment.dataType is None or attachment.data is None:
                extractedData = b""
            elif isinstance(attachment.data, bytes):
                extractedData = attachment.data
            elif issubclass(type(attachment.data), MessageBase):
                extractedData = attachment.data.exportBytes()  # type: ignore

            # Data for parent about children
            if attachment.mimetype:
                mimeType.add(attachment.mimetype.rstrip("\x00"))

            if extractedData == b"":
                # If we can't get data out, skip over.
                continue

            # Create child and give appropriate data
            c = self.add_child_with_data(
                {"action": "extracted"}, extractedData
            )  # might be a password protected attachment
            # supply the mail body text for any unboxing attempts
            if passwordDictionary:
                c.add_data(DataLabel.PASSWORD_DICTIONARY, {}, passwordDictionary)
            c.add_feature_values("filename", filename)
            h = sha256()
            h.update(extractedData)
            hashes.add(h.hexdigest())
            count = count + 1

        if count:
            features["mime_part_count"] = count
            features["mime_part_hash"] = list(hashes)

        if mimeType:
            features["mime_part_type"] = list(mimeType)

        if attachment_types:
            features["attachment"] = list(attachment_types)

    def textAndEmailSplitter(self, data: str) -> tuple[str, str]:
        """TextAndEmailSplitter.

        Lib will now pull a text display along with the email. Split them so we can use them separately.
                  text     email
        format: "abc@abc <abc@abc>"
                        or
                     "abc@abc"
        @param data: string that may be in above format.
        @return (email, text). Text may be an empty string.
        """
        #  Use just the email
        # format: abc@abc <abc@abc>
        start = data.find("<")
        end = data.find(">")

        if -1 == start:
            return (data, "")
        else:
            return (data[start + 1 : end], data[:start])


def main():
    """Run plugin from the command-line."""
    cmdline_run(plugin=AzulPluginMailExtractMsg)


if __name__ == "__main__":
    main()
