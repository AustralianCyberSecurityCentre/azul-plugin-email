"""Test helper functions."""

import unittest

from azul_plugin_email import helpers


class TestHelpers(unittest.TestCase):
    def test_get_words(self):
        """Test word list extraction from email body lists."""
        bodies = [
            b"""
This secure email was sent to: bob.redacted.266@thetire.ca      Wed, 3 May 2017 13:47:21 +0000

RBC Logo

From:                           Royal Bank of Canada
To:                                     bob.redacted.266@thetire.ca
Subject:                        RBC Secure DOC / DOC Security
Date:                           Wed, 3 May 2017 13:47:21 +0000
Password:                       9vXbzz739uCt

Open the SecureMessage.doc attachment by double-clicking or using the "Open" or "View" action within the email application.
Your default DOC viewer software should open automatically. In the "Password" field, enter the password given to you by the sender at RBC and press "OK".
The SecureMessage.doc will be displayed, and any included attachments may now be opened. Large DOC messages may take several minutes to display.

You can access the attachments by simply double-clicking the file.

Attachments:            SecureMessage.doc (42 KB)

Royal Bank of Canada Secure DOC, 1995-2017
""",
            b"""This is some alternate text mate.
""",
        ]

        w = helpers.get_words(bodies, filename="secure.doc")
        print(w)
        self.assertEqual(
            w,
            b"+0000\n13:47:21\n1995-2017\n2017\n9vXbzz739uCt\nAttachments\nBank\nCanada\nDOC\nDate\nFrom\nLarge\nLogo\nMay\nOpen\nPassword\nRBC\nRoyal\nSecure\nSecureMessage.doc\nSecurity\nSubject\nThe\nThis\nView\nWed\nYou\nYour\naccess\naction\nalternate\nand\nany\napplication\nattachment\nattachments\nautomatically\ncan\ndefault\ndisplay\ndisplayed\ndouble-clicking\nemail\nenter\nfield\nfile\ngiven\nincluded\nmate\nmay\nmessages\nminutes\nnow\nopen\nopened\npassword\npress\nsecure\nsecure.doc\nsender\nsent\nseveral\nshould\nsimply\nsoftware\nsome\ntake\ntext\nthe\nusing\nviewer\nwas\nwill\nwithin\nyou",
        )
