"""
mail_headers test suite
=======================
Test the SMTP Mail Header extractor plugin which is really testing the
generic mail header parsing code in template.py

"""

import datetime

from azul_runner import FV, Event, JobResult, State, Uri, test_template

from azul_plugin_email.mail_headers import AzulPluginMailHeaders


class TestExecute(test_template.TestPlugin):
    PLUGIN_TO_TEST = AzulPluginMailHeaders

    def test_attachments(self):
        """A sample with malicious doc attachment"""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_cart(
                        "aaa11162e56abeda3e94b7bf3631ea750b373caafec95c4c2548de57ffda6b69.cart",
                        description="Benign file that has email style header and then encoded content",
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
                        entity_id="aaa11162e56abeda3e94b7bf3631ea750b373caafec95c4c2548de57ffda6b69",
                        features={
                            "mail_address": [FV("person1@email1.com"), FV("person2@email2.com")],
                            "mail_agent": [FV("FoxMail 3.11 Release [xx]")],
                            "mail_date": [FV(datetime.datetime(2011, 4, 10, 2, 17, 11))],
                            "mail_domain": [FV(Uri("email1.com")), FV(Uri("email2.com"))],
                            "mail_extension_header": [FV("X-Mailer"), FV("X-Priority")],
                            "mail_extension_header_value": [
                                FV("3", label="X-Priority"),
                                FV("FoxMail 3.11 Release [xx]", label="X-Mailer"),
                            ],
                            "mail_from": [FV('"Person1" <person1@email1.com>')],
                            "mail_subject": [FV("Hunting Malware in Email")],
                            "mail_to": [FV("person2@email2.com")],
                        },
                    )
                ],
            ),
        )

    def test_nonascii_from(self):
        """Test bugfix where mail with =? encoded 'From' headers were being missed"""
        # sample 7a32d685fc3a9c9a6fe2c2fc9dc03a7e340a068d78ab3b48313532d58ab9d1b7 from vt
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "7a32d685fc3a9c9a6fe2c2fc9dc03a7e340a068d78ab3b48313532d58ab9d1b7", "Malicious phishing email."
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
                        entity_id="7a32d685fc3a9c9a6fe2c2fc9dc03a7e340a068d78ab3b48313532d58ab9d1b7",
                        features={
                            "mail_address": [FV("99b2ca30b@87556.ru"), FV("caf9@14252ef73f1ba9.ru")],
                            "mail_date": [FV(datetime.datetime(2021, 10, 11, 22, 14, 31))],
                            "mail_domain": [FV(Uri("14252ef73f1ba9.ru")), FV(Uri("87556.ru"))],
                            "mail_extension_header": [FV("X-Rejection-Reason")],
                            "mail_extension_header_value": [
                                FV(
                                    "12 - 521 The IP 150.129.5.220 is Blacklisted by invaluement.ik2. --- ",
                                    label="X-Rejection-Reason",
                                )
                            ],
                            "mail_from": [FV("Мила Ромодановская <99b2ca30b@87556.ru>")],
                            "mail_subject": [FV("Ваш баланс по счету № 849351499 пополнен на 236$")],
                            "mail_timezone": [FV("+0200")],
                            "mail_to": [FV("info <caf9@14252ef73f1ba9.ru>")],
                        },
                    )
                ],
            ),
        )
