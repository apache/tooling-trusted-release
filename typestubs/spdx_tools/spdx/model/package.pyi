from datetime import datetime
from dataclasses import field
from beartype.typing import List, Optional, Union
from license_expression import LicenseExpression

from spdx_tools.spdx.model.actor import Actor
from spdx_tools.spdx.model.checksum import Checksum
from spdx_tools.spdx.model.external_reference import ExternalPackageRef
from spdx_tools.spdx.model.package_verification_code import PackageVerificationCode
from spdx_tools.spdx.model.package_purpose import PackagePurpose
from spdx_tools.spdx.model.spdx_no_assertion import SpdxNoAssertion
from spdx_tools.spdx.model.spdx_none import SpdxNone

LicenseType = Union[LicenseExpression, SpdxNoAssertion, SpdxNone]
OptionalLicenseType = Optional[LicenseType]

class Package:
    spdx_id: str
    name: str
    version: Optional[str]
    file_name: Optional[str]
    supplier: Optional[Actor]
    originator: Optional[Actor]
    download_location: str
    files_analyzed: bool
    verification_code: Optional[PackageVerificationCode]
    checksums: List[Checksum]
    homepage: Optional[str]
    source_info: Optional[str]
    license_concluded: Optional[LicenseType]
    license_info_from_files: List[OptionalLicenseType]
    license_declared: Optional[LicenseType]
    license_comment: Optional[str]
    copyright_text: Optional[str]
    summary: Optional[str]
    description: Optional[str]
    comment: Optional[str]
    external_references: List[ExternalPackageRef]
    attribution_texts: List[str]
    primary_package_purpose: Optional[PackagePurpose]
    release_date: Optional[datetime]
    built_date: Optional[datetime]
    valid_until_date: Optional[datetime]

    def __init__(
        self,
        spdx_id: str,
        name: str,
        version: Optional[str] = None,
        file_name: Optional[str] = None,
        supplier: Optional[Actor] = None,
        originator: Optional[Actor] = None,
        download_location: str = "",
        files_analyzed: bool = True,
        verification_code: Optional[PackageVerificationCode] = None,
        checksums: Optional[List[Checksum]] = None,
        homepage: Optional[str] = None,
        source_info: Optional[str] = None,
        license_concluded: Optional[LicenseType] = None,
        license_info_from_files: Optional[List[OptionalLicenseType]] = None,
        license_declared: Optional[LicenseType] = None,
        license_comment: Optional[str] = None,
        copyright_text: Optional[str] = None,
        summary: Optional[str] = None,
        description: Optional[str] = None,
        comment: Optional[str] = None,
        external_references: Optional[List[ExternalPackageRef]] = None,
        attribution_texts: Optional[List[str]] = None,
        primary_package_purpose: Optional[PackagePurpose] = None,
        release_date: Optional[datetime] = None,
        built_date: Optional[datetime] = None,
        valid_until_date: Optional[datetime] = None,
    ) -> None: ...
