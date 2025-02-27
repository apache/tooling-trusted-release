from datetime import datetime
from beartype.typing import List, Optional

from spdx_tools.spdx.model import (
    Actor,
    Annotation,
    ExternalDocumentRef,
    ExtractedLicensingInfo,
    File,
    Package,
    Relationship,
    Snippet,
    Version,
)

class CreationInfo:
    spdx_version: str
    spdx_id: str
    name: str
    document_namespace: str
    creators: List[Actor]
    created: datetime
    creator_comment: Optional[str]
    data_license: str
    external_document_refs: List[ExternalDocumentRef]
    license_list_version: Optional[Version]
    document_comment: Optional[str]

    def __init__(
        self,
        spdx_version: str,
        spdx_id: str,
        name: str,
        document_namespace: str,
        creators: List[Actor],
        created: datetime,
        creator_comment: Optional[str] = None,
        data_license: str = "CC0-1.0",
        external_document_refs: Optional[List[ExternalDocumentRef]] = None,
        license_list_version: Optional[Version] = None,
        document_comment: Optional[str] = None,
    ) -> None: ...

class Document:
    creation_info: CreationInfo
    packages: List[Package]
    files: List[File]
    snippets: List[Snippet]
    annotations: List[Annotation]
    relationships: List[Relationship]
    extracted_licensing_info: List[ExtractedLicensingInfo]

    def __init__(
        self,
        creation_info: CreationInfo,
        packages: Optional[List[Package]] = None,
        files: Optional[List[File]] = None,
        snippets: Optional[List[Snippet]] = None,
        annotations: Optional[List[Annotation]] = None,
        relationships: Optional[List[Relationship]] = None,
        extracted_licensing_info: Optional[List[ExtractedLicensingInfo]] = None,
    ) -> None: ...
