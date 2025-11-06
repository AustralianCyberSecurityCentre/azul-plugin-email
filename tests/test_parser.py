"""
Test cases to exercise several codepaths through olemail parser.
"""

import os
from hashlib import md5
from tempfile import NamedTemporaryFile

from azul_runner.test_utils import FileManager

from azul_plugin_email import parser

SAMPLES = os.path.join(os.path.dirname(__file__), "data", "parser")


def test_invalid_content():
    with NamedTemporaryFile(delete=True) as tmp:
        tmp.write(b"\0xd0\xcf\x1ethis is not an ole file")
        tmp.flush()
        try:
            m = parser.Message(tmp.name)
            assert False
        except (IOError, OSError):
            # expect file type issue
            pass


def test_attachments():
    """
    Test email with attachments and unicode strings.
    """
    fm = FileManager()
    # Email with attachments and unicode strings
    path = fm.download_file_path("3c67dc70854b994e469fc14496d23bf778e718831806ebafc72436c840439f9c")
    m = parser.Message(path)
    assert m.header
    assert m.date == "Mon, 18 Nov 2013 10:26:24 +0200"
    assert m.sender == "Brian Zhou <brizhou@gmail.com>"
    assert m.to == "brianzhou@me.com"
    assert m.cc == "Brian Zhou <brizhou@gmail.com>"
    assert m.subject == "Test for TIF files"
    assert (
        m.body
        == "This is a test email to experiment with the MS Outlook MSG Extractor\r\n\r\n\r\n-- \r\n\r\n\r\nKind regards\r\n\r\n\r\n\r\n\r\nBrian Zhou\r\n\r\n"
    )
    assert len(m.attachments) == 2
    # yes, these are really their filenames, not an error in olefile
    assert m.attachments[0].long_filename == "import OleFileIO.tif"
    assert md5(m.attachments[0].data).hexdigest() == "c1426827ae327cdbfcba9226728e9398"
    assert m.attachments[1].long_filename == "raised value error.tif"
    assert md5(m.attachments[1].data).hexdigest() == "466dd71f5a75c409c69f54e4f90fc82a"


def test_properties_date():
    """
    Generated email without any mail header.
    Need to extract as much as possible from OLE2 properties.
    """
    fm = FileManager()
    # Email with bad strange date and bad header data.
    path = fm.download_file_path("9676ca02b32c15bf47bcf4295131d807a2729c2d1cddc53c4d40b57aa6c6d32b")
    m = parser.Message(path)
    assert not m.header
    assert m.date == "Tue, 23 Feb 2016 14:57:50 +0000"
    assert m.to == "time2talk@online-convert.com"
    assert m.subject == "MSG Test File"
    assert md5(m.body.encode("utf-8")).hexdigest() == "b17416d278091f232fcf999c042543ed"
    # note there appears to be an embedded zip file here but it is not
    # represented as an 'attachment' in the ole2 structure
    assert not m.attachments
