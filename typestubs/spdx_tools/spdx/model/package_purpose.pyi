from enum import Enum, auto

class PackagePurpose(Enum):
    APPLICATION = auto()
    FRAMEWORK = auto()
    LIBRARY = auto()
    CONTAINER = auto()
    OPERATING_SYSTEM = auto()
    DEVICE = auto()
    FIRMWARE = auto()
    SOURCE = auto()
    ARCHIVE = auto()
    FILE = auto()
    INSTALL = auto()
    OTHER = auto()
