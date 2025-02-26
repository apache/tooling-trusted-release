from typing import List, Optional

class PackageVerificationCode:
    value: str
    excluded_files: List[str]

    def __init__(self, value: str, excluded_files: Optional[List[str]] = None) -> None: ...
