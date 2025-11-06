"""
mime_decoder test suite
=======================
Tests the mime_decoder plugins ability to extract and feature MIME
encoded content.

"""

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

from azul_plugin_email.mime_decoder import AzulPluginMimeDecoder


class TestExecute(test_template.TestPlugin):
    PLUGIN_TO_TEST = AzulPluginMimeDecoder

    def test_malicious_attachment(self):
        """An SMTP sample with malicious doc attachment"""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_cart(
                        "aaa11162e56abeda3e94b7bf3631ea750b373caafec95c4c2548de57ffda6b69.cart",
                        description="benign file that has email style header and then encoded content.",
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
                        data=[
                            EventData(
                                hash="834a9c7df9239a4f8de00e8519f5b9f9f5c04c03d910680341fb143641fe45f5", label="text"
                            )
                        ],
                        features={
                            "mime_version": [FV("1.0")],
                            "mime_boundary": [FV("=_NextPart_c5radzbs2htq8jcou4d1yp2")],
                            "mime_part_type": [FV("application/octet-stream"), FV("text/plain")],
                            "mime_part_hash": [
                                FV("7a6b78a4662ceca77e76cd7f2bc08f69a588fc7547db60eb77eb4c328a04c0a8"),
                                FV("834a9c7df9239a4f8de00e8519f5b9f9f5c04c03d910680341fb143641fe45f5"),
                            ],
                            "mime_part_count": [FV(2)],
                            "tag": [FV("trailing_data")],
                        },
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="aaa11162e56abeda3e94b7bf3631ea750b373caafec95c4c2548de57ffda6b69",
                        ),
                        entity_type="binary",
                        entity_id="7a6b78a4662ceca77e76cd7f2bc08f69a588fc7547db60eb77eb4c328a04c0a8",
                        relationship={"action": "extracted", "encoding": "base64"},
                        data=[
                            EventData(
                                hash="7a6b78a4662ceca77e76cd7f2bc08f69a588fc7547db60eb77eb4c328a04c0a8",
                                label="content",
                            ),
                            EventData(
                                hash="08f212365e49d238b484de2f9bf4ace4d8d7e88f82d6f57b349e1277cc834259",
                                label="password_dictionary",
                            ),
                        ],
                        features={
                            "mime_content_encoding": [FV("base64")],
                            "mime_content_type": [FV("application/octet-stream")],
                            "filename": [FV("document.doc")],
                        },
                    ),
                ],
                data={
                    "7a6b78a4662ceca77e76cd7f2bc08f69a588fc7547db60eb77eb4c328a04c0a8": b"",
                    "08f212365e49d238b484de2f9bf4ace4d8d7e88f82d6f57b349e1277cc834259": b"",
                    "834a9c7df9239a4f8de00e8519f5b9f9f5c04c03d910680341fb143641fe45f5": b"",
                },
            ),
        )

    def test_malicious_attachment_append(self):
        """An SMTP sample with malicious doc attachment"""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_cart(
                        "aaa11162e56abeda3e94b7bf3631ea750b373caafec95c4c2548de57ffda6b69.cart",
                        description="benign file that has email style header and then encoded content.",
                    ),
                )
            ],
            config={"appended_data_as_child": True},
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="aaa11162e56abeda3e94b7bf3631ea750b373caafec95c4c2548de57ffda6b69",
                        data=[
                            EventData(
                                hash="834a9c7df9239a4f8de00e8519f5b9f9f5c04c03d910680341fb143641fe45f5", label="text"
                            )
                        ],
                        features={
                            "mime_version": [FV("1.0")],
                            "mime_boundary": [FV("=_NextPart_c5radzbs2htq8jcou4d1yp2")],
                            "mime_part_type": [FV("application/octet-stream"), FV("text/plain")],
                            "mime_part_hash": [
                                FV("7a6b78a4662ceca77e76cd7f2bc08f69a588fc7547db60eb77eb4c328a04c0a8"),
                                FV("834a9c7df9239a4f8de00e8519f5b9f9f5c04c03d910680341fb143641fe45f5"),
                            ],
                            "mime_part_count": [FV(2)],
                            "tag": [FV("trailing_data")],
                        },
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="aaa11162e56abeda3e94b7bf3631ea750b373caafec95c4c2548de57ffda6b69",
                        ),
                        entity_type="binary",
                        entity_id="7a6b78a4662ceca77e76cd7f2bc08f69a588fc7547db60eb77eb4c328a04c0a8",
                        relationship={"action": "extracted", "encoding": "base64"},
                        data=[
                            EventData(
                                hash="7a6b78a4662ceca77e76cd7f2bc08f69a588fc7547db60eb77eb4c328a04c0a8",
                                label="content",
                            ),
                            EventData(
                                hash="08f212365e49d238b484de2f9bf4ace4d8d7e88f82d6f57b349e1277cc834259",
                                label="password_dictionary",
                            ),
                        ],
                        features={
                            "mime_content_encoding": [FV("base64")],
                            "mime_content_type": [FV("application/octet-stream")],
                            "filename": [FV("document.doc")],
                        },
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="aaa11162e56abeda3e94b7bf3631ea750b373caafec95c4c2548de57ffda6b69",
                        ),
                        entity_type="binary",
                        entity_id="11e4cd894398ff7082a80b224cc3f86eefa1b221c81b93d13786d578d9d0916c",
                        relationship={"action": "extracted", "type": "epilogue"},
                        data=[
                            EventData(
                                hash="11e4cd894398ff7082a80b224cc3f86eefa1b221c81b93d13786d578d9d0916c",
                                label="content",
                            )
                        ],
                    ),
                ],
                data={
                    "7a6b78a4662ceca77e76cd7f2bc08f69a588fc7547db60eb77eb4c328a04c0a8": b"",
                    "08f212365e49d238b484de2f9bf4ace4d8d7e88f82d6f57b349e1277cc834259": b"",
                    "834a9c7df9239a4f8de00e8519f5b9f9f5c04c03d910680341fb143641fe45f5": b"",
                    "11e4cd894398ff7082a80b224cc3f86eefa1b221c81b93d13786d578d9d0916c": b"",
                },
            ),
        )

    def test_malicious_failed_delivery(self):
        """An SMTP sample with 'undelivered' notice including malicious attachment"""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "d08e83ab9c2f68e46f59b6c3e0d6ec45d040f73f081e8d04183b9a196445f618",
                        "Malicious email, with a malicious attachment.",
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
                        entity_id="d08e83ab9c2f68e46f59b6c3e0d6ec45d040f73f081e8d04183b9a196445f618",
                        data=[
                            EventData(
                                hash="4cbca66ff817230499cbb5112e3eda494a4b68293c19e7acf9e5fe8499356b57", label="text"
                            ),
                            EventData(
                                hash="2e78f0e4b4916c5faf97c85b8dce063241037641a2091d285b554534cf15c628", label="text"
                            ),
                        ],
                        features={
                            "mime_version": [FV("1.0")],
                            "mime_boundary": [FV("6633CC6EEA.1234567891/sextant01b.mail.net")],
                            "mime_part_type": [
                                FV("application/msword"),
                                FV("message/delivery-status"),
                                FV("message/rfc822"),
                                FV("text/html"),
                                FV("text/plain"),
                            ],
                            "mime_part_hash": [
                                FV("0f57baeb3070bf7a806f004ab61243aaf1b16f328e0c5f96d0c9128294d95b2c"),
                                FV("2e78f0e4b4916c5faf97c85b8dce063241037641a2091d285b554534cf15c628"),
                                FV("3b79d4e7a8d91867e958ab89bd02af9e48b4047951207046705c1d7be55b882e"),
                                FV("48ad77696cdfbcbe92f925bc1c3ed136abd09a9dc514b9ccd88c8cf230c86570"),
                                FV("4cbca66ff817230499cbb5112e3eda494a4b68293c19e7acf9e5fe8499356b57"),
                                FV("9b46e9e0423713d519b2820a602ffe0f1a06b85d8c98e287810b8501ad421ca5"),
                            ],
                            "mime_part_count": [FV(8)],
                            "tag": [FV("trailing_data")],
                        },
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="d08e83ab9c2f68e46f59b6c3e0d6ec45d040f73f081e8d04183b9a196445f618",
                        ),
                        entity_type="binary",
                        entity_id="3b79d4e7a8d91867e958ab89bd02af9e48b4047951207046705c1d7be55b882e",
                        relationship={"action": "extracted", "encoding": "none"},
                        data=[
                            EventData(
                                hash="3b79d4e7a8d91867e958ab89bd02af9e48b4047951207046705c1d7be55b882e",
                                label="content",
                            )
                        ],
                        features={"mime_content_type": [FV("message/rfc822")]},
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="d08e83ab9c2f68e46f59b6c3e0d6ec45d040f73f081e8d04183b9a196445f618",
                        ),
                        entity_type="binary",
                        entity_id="0f57baeb3070bf7a806f004ab61243aaf1b16f328e0c5f96d0c9128294d95b2c",
                        relationship={"action": "extracted", "encoding": "base64"},
                        data=[
                            EventData(
                                hash="0f57baeb3070bf7a806f004ab61243aaf1b16f328e0c5f96d0c9128294d95b2c",
                                label="content",
                            ),
                            EventData(
                                hash="dbb892ee04c9d011cd5ea6026d1a43d6147e37bebf30d36e8d1afc7f36947db0",
                                label="password_dictionary",
                            ),
                        ],
                        features={
                            "mime_content_encoding": [FV("base64")],
                            "mime_content_type": [FV("application/msword")],
                            "filename": [FV("Hazards and Risk.doc")],
                        },
                    ),
                ],
                data={
                    "3b79d4e7a8d91867e958ab89bd02af9e48b4047951207046705c1d7be55b882e": b"",
                    "0f57baeb3070bf7a806f004ab61243aaf1b16f328e0c5f96d0c9128294d95b2c": b"",
                    "dbb892ee04c9d011cd5ea6026d1a43d6147e37bebf30d36e8d1afc7f36947db0": b"",
                    "4cbca66ff817230499cbb5112e3eda494a4b68293c19e7acf9e5fe8499356b57": b"",
                    "2e78f0e4b4916c5faf97c85b8dce063241037641a2091d285b554534cf15c628": b"",
                },
            ),
        )

    def test_mime_document(self):
        """MS Word MIME encoded document"""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "0dc315e0b3d9f4098ea5cac977b9814e3c6e9116cf296c1bbfcb3ab95c72ca99",
                        "Malicious email (MIME HTML Archive), trojan, cve20120158.",
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
                        entity_id="0dc315e0b3d9f4098ea5cac977b9814e3c6e9116cf296c1bbfcb3ab95c72ca99",
                        features={
                            "mime_version": [FV("1.0")],
                            "mime_boundary": [FV("----=_NextPart_01CD27E7.8767FC40")],
                            "mime_part_type": [FV("text/html"), FV("text/xml")],
                            "mime_part_hash": [
                                FV("3ea46fd3df2ae073caec2d66c35c31c3e786d9f9b59fcf0d6ea9d344fdc71bc5"),
                                FV("564e9b57833f25ce7a258fab4e2e2ac48eb7e58960280de41c1b4e5ad17c159e"),
                                FV("dc860f9bffb3b362186a3a3211fe49bd5f2d573fd92fb4e1e4d008cce1dcc1fb"),
                            ],
                            "mime_part_count": [FV(3)],
                            "tag": [FV("trailing_data")],
                        },
                    )
                ],
            ),
        )

    def test_mime_web_archive(self):
        """MIME encoded web archive"""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_cart(
                        "8ad5920ebdb440e5fd72fc07f79896266f5b9d7c0638a5602676dad05c5f43ea.cart",
                        description="Mime Web Archive.",
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
                        entity_id="8ad5920ebdb440e5fd72fc07f79896266f5b9d7c0638a5602676dad05c5f43ea",
                        features={
                            "mime_version": [FV("1.0")],
                            "mime_boundary": [FV("----=_NextPart_000_0000_01D1E1EF.25988180")],
                            "mime_part_type": [FV("image/png"), FV("text/css")],
                            "mime_part_hash": [
                                FV("021d2ac131d88dbdfa1f27ba03bec85c1fed89e4fc80680ac9ea58600c082336"),
                                FV("15f2540031a26c5729db500e48eca76b193cae78444e04af5d0e6b8385346db7"),
                                FV("75af436ad40613f3d2d1d6dd4e0d9954fad71284376282695ec3f6e94f997483"),
                                FV("b34b759d9ca3593982784a04df7d87b21fdb7ac5c7781b28ee112b532c23d642"),
                                FV("b8ff8391354c85814d14f8155667ba63322c497c88bec177db40d3085a0b5f50"),
                                FV("bba224748ef64de1179a37324f509af08314f3236047f5a519bf45d6e7f0206e"),
                            ],
                            "mime_part_count": [FV(6)],
                        },
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="8ad5920ebdb440e5fd72fc07f79896266f5b9d7c0638a5602676dad05c5f43ea",
                        ),
                        entity_type="binary",
                        entity_id="75af436ad40613f3d2d1d6dd4e0d9954fad71284376282695ec3f6e94f997483",
                        relationship={"action": "extracted", "encoding": "base64"},
                        data=[
                            EventData(
                                hash="75af436ad40613f3d2d1d6dd4e0d9954fad71284376282695ec3f6e94f997483",
                                label="content",
                            )
                        ],
                        features={
                            "mime_content_encoding": [FV("base64")],
                            "mime_content_type": [FV("image/png")],
                            "mime_content_location": [FV("http://server/files/logo_180px.png")],
                            "filename": [FV("logo_180px.png")],
                        },
                    ),
                ],
                data={"75af436ad40613f3d2d1d6dd4e0d9954fad71284376282695ec3f6e94f997483": b""},
            ),
        )

    def test_wrong_file_type(self):
        """Ensure we don't raise features from incorrect file"""
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
                state=State(
                    State.Label.OPT_OUT,
                    message="No match found in header for pattern: b'^([-\\\\w]+): ([^\\\\r\\\\n;])'",
                )
            ),
        )
