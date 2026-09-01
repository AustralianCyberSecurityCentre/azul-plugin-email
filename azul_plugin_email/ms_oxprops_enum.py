"""Exchange server protocols enums.

Exchange Server Protocols Master Property List
https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/

Useful for pulling data from .msg property storage
"""

from enum import Enum


class MS_OXPROPS(Enum):
    """Demystify MS hex property strings.

    xx xx xx 40    |   Data type: PtypTime
    xx xx xx 1F    |   Data type: PtypString
    """

    PidTagClientSubmitTime = "00390040"
    """
    Canonical name: PidTagClientSubmitTime
    Description: Contains the current time, in UTC, when the email message is submitted.
    Property ID: 0x0039
    Data type: PtypTime, 0x0040
    """

    PidTagCreationTime = "30070040"
    """
    Canonical name: PidTagCreationTime
    Description: Contains the time, in UTC, that the object was created.
    Property ID: 0x3007
    Data type: PtypTime, 0x0040
    """

    PidTagLastModificationTime = "30080040"
    """
    Canonical name: PidTagLastModificationTime
    Description: Contains the time, in UTC, of the last modification to the object.
    Property ID: 0x3008
    Data type: PtypTime, 0x0040
    """

    PidTagMessageDeliveryTime = "0E060040"
    """
    Canonical name: PidTagMessageDeliveryTime
    Description: Specifies the time (in UTC) when the server received the message.
    Property ID: 0x0E06
    Data type: PtypTime, 0x0040
    """

    PidTagSubject = "0037001F"
    """
    Canonical name: PidTagSubject
    Description: Contains the subject of the email message.
    Property ID: 0x0037
    Data type: PtypString, 0x001F
    """
