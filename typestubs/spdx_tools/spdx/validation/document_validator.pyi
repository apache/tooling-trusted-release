from beartype.typing import List, Optional

from spdx_tools.spdx.model import Document
from spdx_tools.spdx.validation.validation_message import ValidationMessage

def validate_full_spdx_document(document: Document, spdx_version: Optional[str] = None) -> List[ValidationMessage]: ...
