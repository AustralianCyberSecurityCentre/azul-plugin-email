"""Outlook email '.msg' decoder / extractor

This plugin uses 'extract-msg' https://github.com/TeamMsgExtractor/msg-extractor to 
decode and extract content and features from '.msg' files. 
"""
from hashlib import sha256

from extract_msg import openMsg
from extract_msg.exceptions import UnsupportedMSGTypeError, UnrecognizedMSGTypeError
from extract_msg.msg_classes.message import Message
from extract_msg.msg_classes.message_base import MessageBase
from extract_msg.msg_classes.calendar import Calendar
from extract_msg.msg_classes.meeting_related import MeetingRelated

from azul_runner import DataLabel, Feature, FeatureType, Job, add_settings, cmdline_run, BinaryPlugin

from .helpers import get_words
from .template import AzulPluginMailParser


class AzulPluginMailExtractMsg(AzulPluginMailParser):
    """"""

    VERSION = "2026.08.24"
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


    def execute(self, job:Job):
        """
        Extracts attachment as children and features corresponding mail headers.
        """
        path = job.get_data().get_filepath()
        features: dict[str, str | int | list[str]] = {}
        try:
            '''
            Attempt to open the file. May fail. Lots of arguments to re-attempt with
            '''
            msg = openMsg(path)
        except UnsupportedMSGTypeError as ex:
            """
            An exception that is raised when an MSG class is recognized by not
            supported.
            """
            # TODO HANDLE
            return
        except UnrecognizedMSGTypeError as ex:
            """
            An exception that is raised when the module cannot determine how to properly
            open a specific class of MSG file.
            """
            features["processing_failure"] = "Unable to parse OLE file: %s" % str(ex)
            self.add_many_feature_values(features)
            return
        except OSError as ex:
            features["processing_failure"] = "Unable to parse OLE file: %s" % str(ex)
            self.add_many_feature_values(features)
            return

        # NOTE At this point extract_msg should have done all the heavy lifting required
        # Now we just need to map data to features

        if (type(msg) is not Message):
            return
        
        ## body (ASCII) may not exist, try htmlBody and rftBody
        extractedBody = None
        if msg.body:
            extractedBody = msg.body.encode("utf-8")
        elif msg.htmlBody:
            extractedBody = msg.htmlBody
        elif msg.rtfBody:
            extractedBody = msg.rtfBody
        else:
            self.logger.warning("body either does not exist or can't be parse")

        # raise body as txt report
        if extractedBody:
            self.add_data(DataLabel.TEXT, {}, extractedBody)

        # Let template rip and format all the headers pulled from the msg
        if msg.header:
            features = self.parse_headers(msg.header)

        # there may be cases where the mime headers fail to parse from
        # the .msg but the basic fields can still be extracted from the
        # specific ole2 stream equivalents
        # TODO confirm working
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

        '''
        Attachments: only directly pull one level deep information. All children
        of correct file type will get processed by this plugin again, and we'll
        let that run(s) pull out the deeper data. Minimally feature tag the children
        with data that won't be available on the next run.
        '''
        
        # reuse the mime decoders child features as the .msg is really just
        # derived from a mime encoded mail anyway..although we only include
        # attachments not any mime parts that were used as the email body.
        hashes = set()
        count = 0
        # extract any attachments as child entities
        for attachment in msg.attachments:

            attachmentData = b''
            filename = attachment.longFilename or attachment.shortFilename

            if not attachment.dataType:
                self.logger.info("Either attachment would raise exception or is an empty attachment")
                continue
            elif (issubclass(attachment.dataType, MessageBase)):
                # Attachment is some kind of embedded .msg . Will be contained
                # in attachment.data

                filename = attachment.getFilename()

                if (attachment.dataType is Message and type(attachment.data) is Message):
                    # Another email message was attached to this email. If there are suspect or invalid
                    # embeds, maintain them.
                    attachmentData = attachment.data.exportBytes(allowBadEmbed=True)
                elif (issubclass(attachment.dataType, Calendar)):

                    attachmentData = attachment.data.exportBytes(allowBadEmbed=True)

                    if (issubclass(attachment.dataType, MeetingRelated)):
                        print('meeting')
                        # TODO     
                    else:
                        # appointment: only non-meeting related message under calendar class
                        if attachment.data.subject:
                            # Use appoinment subject as name if it exists
                            filename = attachment.data.subject + '.msg'
                        elif msg.filename:
                            # Use the message attachment is from for name
                            filename = msg.filename + '.appointment.msg'
                        else:
                            # As final fallback use the messageID of the attachment
                            filename = attachment.data.messageID + '.appointment.msg'
                else:
                    # is some kind of other message: journal, contact, post, stickynote, taskrequest, task
                    print("diffrent submessage type")
                    # TODO

            elif (attachment.dataType is bytes and type(attachment.data) is bytes):
                # Can directly use the extracted data
                attachmentData = attachment.data
            else:
                self.logger.warning(f"Attachment is of unhandled type: {attachment.dataType}")
                continue

            c = self.add_child_with_data({"action": "extracted"}, attachmentData)  # might be a password protected attachment
            # supply the mail body text for any unboxing attempts
            if extractedBody:
                c.add_data(DataLabel.PASSWORD_DICTIONARY, {}, get_words([extractedBody], filename))
            c.add_feature_values("filename", filename)
            h = sha256()
            h.update(attachmentData)
            hashes.add(h.hexdigest())
            count = count + 1

        if count:
            features["mime_part_count"] = count
            features["mime_part_hash"] = list(hashes)


        self.add_many_feature_values(features)

def main():
    """Run plugin from the command-line."""
    cmdline_run(plugin=AzulPluginMailExtractMsg)


if __name__ == "__main__":
    main()