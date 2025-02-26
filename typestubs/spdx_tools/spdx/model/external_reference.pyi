from enum import Enum, auto
from beartype.typing import Optional

class ExternalPackageRefCategory(Enum):
    SECURITY = auto()
    PACKAGE_MANAGER = auto()
    PERSISTENT_ID = auto()
    OTHER = auto()

class ExternalPackageRef:
    category: ExternalPackageRefCategory
    reference_type: str
    locator: str
    comment: Optional[str]

    def __init__(
        self,
        category: ExternalPackageRefCategory,
        reference_type: str,
        locator: str,
        comment: Optional[str] = None
    ) -> None: ...
