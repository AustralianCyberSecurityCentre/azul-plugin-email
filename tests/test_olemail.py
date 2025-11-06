"""
test_olemail
============

Test the olemail plugin feature and attachment extract.

"""

import datetime

from azul_runner import (
    FV,
    Event,
    EventData,
    EventParent,
    Filepath,
    JobResult,
    State,
    Uri,
    test_template,
)

from azul_plugin_email.olemail import AzulPluginOleMail


class TestExecute(test_template.TestPlugin):
    PLUGIN_TO_TEST = AzulPluginOleMail

    def test_attachments(self):
        """A sample with malicious doc attachment"""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "b94e9620d883da9c8d445725e55793bbe51b5fc7828819eaea86245f10e566ae",
                        "Malicious Outlook email with attachment.",
                    ),
                )
            ]
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="b94e9620d883da9c8d445725e55793bbe51b5fc7828819eaea86245f10e566ae",
                        data=[
                            EventData(
                                hash="655b7faff635b22dc04cd7772d023f85122897b3a17f8e6ceb1ef033a0ccba71", label="text"
                            )
                        ],
                        features={
                            "mail_address": [
                                FV("cashier@toinfiniti.com"),
                                FV("prvs=0422c5592=cashier@toinfiniti.com"),
                                FV("tn3538@pioneercredit.net"),
                            ],
                            "mail_agent": [FV("Microsoft Windows Live Mail 16.4.3528.331")],
                            "mail_date": [FV(datetime.datetime(2016, 8, 29, 14, 38, 35))],
                            "mail_domain": [FV(Uri("pioneercredit.net")), FV(Uri("toinfiniti.com"))],
                            "mail_extension_header": [
                                FV("X-Accept-Language"),
                                FV("X-Auto-Response-Suppress"),
                                FV("X-C2ProcessedOrg"),
                                FV("X-IronPort-AV"),
                                FV("X-IronPort-Anti-Spam-Filtered"),
                                FV("X-IronPort-Anti-Spam-Result"),
                                FV("X-MS-Exchange-Organization-AVStamp-Enterprise"),
                                FV("X-MS-Exchange-Organization-AuthAs"),
                                FV("X-MS-Exchange-Organization-AuthSource"),
                                FV("X-MS-Exchange-Organization-Network-Message-Id"),
                                FV("X-MSMail-Priority"),
                                FV("X-Mailer"),
                                FV("X-MimeOLE"),
                                FV("X-Priority"),
                            ],
                            "mail_extension_header_value": [
                                FV("1.0", label="X-MS-Exchange-Organization-AVStamp-Enterprise"),
                                FV("3", label="X-Priority"),
                                FV("7b8cb419-8e1c-4e60-bc2d-39e04995c010", label="X-C2ProcessedOrg"),
                                FV(
                                    "9d7ea3fd-31cb-4d75-8c4a-08d3d01a4ce6",
                                    label="X-MS-Exchange-Organization-Network-Message-Id",
                                ),
                                FV(
                                    "A0EPHQDvR8RXmPAsPtFcGQEBAQEBEQEBAQEBAQEBAQEBAQEBEAEBAQEBAQEBgngBAQEBAXV8hjuGVKsZggAgh0c/DQEBAQEBAQEBAQEBAhABAQEBAQgLCwcZL0EQgWEYgQAsGDgqGyI/CgYhEw4CBA0EKgMEGSSIL54Nj2WGLIkQDBcOhTZugW2CaoUMgjYrgi8BBJdFggoBgz2Bc2+DAYdhARVOhA+DAYYKkD1IAYJQgXNUgT+FDQEBAQ",
                                    label="X-IronPort-Anti-Spam-Result",
                                ),
                                FV("Anonymous", label="X-MS-Exchange-Organization-AuthAs"),
                                FV("DR, OOF, AutoReply", label="X-Auto-Response-Suppress"),
                                FV("DRVEX01.marinerfinance.com", label="X-MS-Exchange-Organization-AuthSource"),
                                FV(
                                    'E=Sophos;i="5.28,596,1464667200"; \r\n   d="doc\'32,178,179?scan\'32,178,179,208,32,178,179";a="9092396"',
                                    label="X-IronPort-AV",
                                ),
                                FV("Microsoft Windows Live Mail 16.4.3528.331", label="X-Mailer"),
                                FV("Normal", label="X-MSMail-Priority"),
                                FV("Produced By Microsoft MimeOLE V16.4.3528.331", label="X-MimeOLE"),
                                FV("en-us", label="X-Accept-Language"),
                                FV("true", label="X-IronPort-Anti-Spam-Filtered"),
                            ],
                            "mail_from": [FV('"cashier@toinfiniti.com" <cashier@toinfiniti.com>')],
                            "mail_message_id": [FV("<D39C2B1D.DFFF1C3E@toinfiniti.com>")],
                            "mail_return_path": [FV("prvs=0422c5592=cashier@toinfiniti.com")],
                            "mail_subject": [FV("Re: formal complaint")],
                            "mail_timezone": [FV("-0400")],
                            "mail_to": [FV("<tn3538@pioneercredit.net>")],
                            "mime_part_count": [FV(1)],
                            "mime_part_hash": [FV("f83dab5e27d17dec0c491d4d8587f08b5b684b5782c7a91d529d9a891420829d")],
                        },
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="b94e9620d883da9c8d445725e55793bbe51b5fc7828819eaea86245f10e566ae",
                        ),
                        entity_type="binary",
                        entity_id="f83dab5e27d17dec0c491d4d8587f08b5b684b5782c7a91d529d9a891420829d",
                        relationship={"action": "extracted"},
                        data=[
                            EventData(
                                hash="f83dab5e27d17dec0c491d4d8587f08b5b684b5782c7a91d529d9a891420829d",
                                label="content",
                            ),
                            EventData(
                                hash="13cb4fb56aac4bf9b7804a4deadfd3cde4d9f83f9655cd0ad3b9c5a657cfc7ff",
                                label="password_dictionary",
                            ),
                        ],
                        features={"filename": [FV(Filepath("complaint_18485.doc"))]},
                    ),
                ],
                data={
                    "f83dab5e27d17dec0c491d4d8587f08b5b684b5782c7a91d529d9a891420829d": b"",
                    "13cb4fb56aac4bf9b7804a4deadfd3cde4d9f83f9655cd0ad3b9c5a657cfc7ff": b"",
                    "655b7faff635b22dc04cd7772d023f85122897b3a17f8e6ceb1ef033a0ccba71": b"",
                },
            ),
        )

    def test_missing_headers(self):
        """A sample without mime headers stream"""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "9676ca02b32c15bf47bcf4295131d807a2729c2d1cddc53c4d40b57aa6c6d32b", "Begign Outlook email."
                    ),
                )
            ]
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="9676ca02b32c15bf47bcf4295131d807a2729c2d1cddc53c4d40b57aa6c6d32b",
                        data=[
                            EventData(
                                hash="663a3268118c3cd710ebd73c79a59a9026308eec4a01a0ecb6cdc7f2004630ff", label="text"
                            )
                        ],
                        features={
                            "mail_date": [FV(datetime.datetime(2016, 2, 23, 14, 57, 50))],
                            "mail_subject": [FV("MSG Test File")],
                            "mail_timezone": [FV("+0000")],
                            "mail_to": [FV("time2talk@online-convert.com")],
                        },
                    )
                ],
                data={"663a3268118c3cd710ebd73c79a59a9026308eec4a01a0ecb6cdc7f2004630ff": b""},
            ),
        )

    def test_cannot_process(self):
        """Incomplete OLE mail file - terminal error"""
        # Do we still want to handle like this in AZUL 3?
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "e7e8a42e47ca609716010907f06f465b0f11c3b9e9949961781c9199c8a968f3",
                        "Corrupted file created with another file from VT. See azul_test_files.",
                    ),
                )
            ]
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="e7e8a42e47ca609716010907f06f465b0f11c3b9e9949961781c9199c8a968f3",
                        features={"processing_failure": [FV("Unable to parse OLE file: incomplete OLE sector")]},
                    )
                ],
            ),
        )

    def test_email_with_hex_values(self):
        """Test handling an email that also contains hex values which can break decoding."""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "4ae594fc5c4708b3ab4e93dc52dfa3e373da4cd382500d544ef5f305e625b005",
                        "Malicious Outlook email, downloader, malware family guloader.",
                    ),
                )
            ]
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="4ae594fc5c4708b3ab4e93dc52dfa3e373da4cd382500d544ef5f305e625b005",
                        data=[
                            EventData(
                                hash="2ddacf3a16f73a1abf2a25955b45c5d342cc17ecefa21d7098b9092b8cb0727c", label="text"
                            )
                        ],
                        features={
                            "mail_address": [FV("info@areacars.de")],
                            "mail_agent": [FV("Zimbra 8.8.15_GA_3888 (ZimbraWebClient - FF123 (Win)/8.8.15_GA_3890)")],
                            "mail_date": [FV(datetime.datetime(2024, 3, 6, 23, 41, 25))],
                            "mail_domain": [FV("areacars.de")],
                            "mail_extension_header": [
                                FV("X-AuditID"),
                                FV("X-Brightmail-Tracker"),
                                FV("X-MS-Exchange-Organization-AuthAs"),
                                FV("X-MS-Exchange-Organization-AuthMechanism"),
                                FV("X-MS-Exchange-Organization-AuthSource"),
                                FV("X-MS-Exchange-Organization-Network-Message-Id"),
                                FV("X-MS-Exchange-Processed-By-BccFoldering"),
                                FV("X-MS-Exchange-Transport-EndToEndLatency"),
                                FV("X-Mailer"),
                                FV("X-Originating-IP"),
                                FV("X-Virus-Scanned"),
                            ],
                            "mail_extension_header_value": [
                                FV("00:00:00.2416638", label="X-MS-Exchange-Transport-EndToEndLatency"),
                                FV("10", label="X-MS-Exchange-Organization-AuthMechanism"),
                                FV("15.02.1118.040", label="X-MS-Exchange-Processed-By-BccFoldering"),
                                FV(
                                    "9bf99ea5-d852-4bad-30ad-08dc3e370b4c",
                                    label="X-MS-Exchange-Organization-Network-Message-Id",
                                ),
                                FV(
                                    "H4sIAAAAAAAAA3VTb1AUZRjnuT3vFmJtOXB4vXRm25qJ0Q5BuQTz+vOBESrJJj+k06Tr3svd\r\n\t5rF7s7s0UFo3qZGHUwfpB8EDtJQSIszxD1J6d1YzMDEBijKj9gdKb6S8yC9OOme7twdD07Qf\r\n\tfvN7nvd5fs/v3X2WJGxJq53EdSqWRc7HWrLM854PMY6X7sdxUbivoPTn/nvwDFScaG43r4ON\r\n\tAVjNiaKkcipm3FjhXez6Z9cw5eluptxRwwk+lqmWZB6vF3G1i63mfApmGcHtYktYxu/jeFyD\r\n\tRdXF+mXsx6KbfSqL+c+zWqsTRAaLvOQWRI+LrXz5RUdpqbPMUbz5Gu293tRr9ncmi+pOh0LW\r\n\tACSuLgsCSSK6BH3ewwUhk8yjF6Fw6+S8IGSRNvorQJ9dP5kOvgAUbj9rMYLDgOKXj1uN4BCg\r\n\txKeX0mVRQN92dMPsSWf4uFlXRvQy1Ppb3DRbdaF3jDCCY4Ain1w16VVmegmK77iU4hZ6MTrz\r\n\twZBF5xRdiQJ/nUjlM+nn0O2/b6TnNQDa03MkNSJXawi8O51uyEED+39N5Qn6FXTlwMdg2GDQ\r\n\t0dGoxeBVqD/yp8W4OIsGugbTfBUav5VIDQP6PUDRvUQIUMsc2ZY5sgZ/DN1rGyUMvhQdOTiV\r\n\t5pWoZbLTYvC1aNfYeJo/jPY2/mLtAOtRQPq3L3xD4FVJFjiHgj21sqQU+tUvQduqsVXN209D\r\n\tPFEQAxMJMVhImtgF1FL+BrbN3yK5672c4t0k1/qwEoNHNeGJ3q5hsJtFScRsHuVMxLGNcnP1\r\n\tb2JZmil7QXvPTYR9AS+JqrZSm4qdZcVlzhXO5StLS5b/T5rNpxa1alq0R1vhrVhbQXlGzkRa\r\n\tY+AgSbpnuh3Tu+82T8/MR9TETa0nR8YeXFct+NS5TZk6ZMUAkdma0UPf60YVP1ejCB6jaBB4\r\n\tcnDnua8J8lYKo6d0PNWnY/cZHcOjIxo2nr+oYVMK7wy1Rgly8Pa5KGFLebDnU76k7luX9taK\r\n\tsxZm/thRWGzPpSAjI8OWrV2qRlD/fX4T8klgc6ktdzWVbEFUZ/3ZA7CrfeSbaGJo6r78arCh\r\n\tbOf+ge/mj2wI7rtTlTdeG5us/yPimZBMSVv47c3lMirak7utP9RNPfJQW7jnQ+WdJz86HOmI\r\n\tbFu4nXx83fD7x1a6f3rid3djbEeO2rCRq3h935rCrmyp4Olm+4YVwz8GmoY6km1vlfOvPWCq\r\n\t6PvhwO6TU/6qB1mz4uWKlxCywv0Drx/EBZEEAAA=",
                                    label="X-Brightmail-Tracker",
                                ),
                                FV("Internal", label="X-MS-Exchange-Organization-AuthAs"),
                                FV("SVPEX03W.victoria.portugal", label="X-MS-Exchange-Organization-AuthSource"),
                                FV(
                                    "Zimbra 8.8.15_GA_3888 (ZimbraWebClient - FF123 (Win)/8.8.15_GA_3890)",
                                    label="X-Mailer",
                                ),
                                FV("[102.89.34.72]", label="X-Originating-IP"),
                                FV("amavisd-new at polarismedia.de", label="X-Virus-Scanned"),
                                FV("d53a927d-a9d3f70000003cd4-f9-65e8ff4ff26b", label="X-AuditID"),
                            ],
                            "mail_from": [FV("Info <info@areacars.de>")],
                            "mail_message_id": [FV("<876047970.2509189.1709768485002.JavaMail.zimbra@areacars.de>")],
                            "mail_return_path": [FV("info@areacars.de")],
                            "mail_subject": [FV("JUSTIFICANTE DE PAGO")],
                            "mail_timezone": [FV("+0100")],
                            "mail_to": [FV("undisclosed-recipients:")],
                            "mime_part_count": [FV(1)],
                            "mime_part_hash": [FV("9a7368c9210f500fae07a432c2b56da62a5ba86991dcc0afa350a651ab34073e")],
                        },
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="4ae594fc5c4708b3ab4e93dc52dfa3e373da4cd382500d544ef5f305e625b005",
                        ),
                        entity_type="binary",
                        entity_id="9a7368c9210f500fae07a432c2b56da62a5ba86991dcc0afa350a651ab34073e",
                        relationship={"action": "extracted"},
                        data=[
                            EventData(
                                hash="9a7368c9210f500fae07a432c2b56da62a5ba86991dcc0afa350a651ab34073e",
                                label="content",
                            ),
                            EventData(
                                hash="05b5636be7bb7606a4365460243ef3a4a9087ad7f5644763b98b3213bc15ccce",
                                label="password_dictionary",
                            ),
                        ],
                        features={"filename": [FV("Pago Transferencias 897877667.rar")]},
                    ),
                ],
                data={
                    "9a7368c9210f500fae07a432c2b56da62a5ba86991dcc0afa350a651ab34073e": b"",
                    "05b5636be7bb7606a4365460243ef3a4a9087ad7f5644763b98b3213bc15ccce": b"",
                    "2ddacf3a16f73a1abf2a25955b45c5d342cc17ecefa21d7098b9092b8cb0727c": b"",
                },
            ),
        )
