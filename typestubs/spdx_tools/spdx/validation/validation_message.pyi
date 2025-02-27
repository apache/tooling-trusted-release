from enum import Enum
from beartype.typing import Optional

class SpdxElementType(Enum):
    DOCUMENT: str
    CREATION_INFO: str
    PACKAGE: str
    FILE: str
    SNIPPET: str
    ANNOTATION: str
    RELATIONSHIP: str
    EXTRACTED_LICENSING_INFO: str

class ValidationContext:
    spdx_id: str
    element_type: SpdxElementType

    def __init__(self, spdx_id: str, element_type: SpdxElementType) -> None: ...

class ValidationMessage:
    validation_message: str
    validation_context: ValidationContext

    def __init__(self, validation_message: str, validation_context: ValidationContext) -> None: ...
