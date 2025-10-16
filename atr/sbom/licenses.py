# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

from __future__ import annotations

from . import constants, models
from .spdx import license_expression_atoms


def check(
    bom_value: models.bom.Bom,
) -> tuple[list[models.licenses.Issue], list[models.licenses.Issue]]:
    warnings: list[models.licenses.Issue] = []
    errors: list[models.licenses.Issue] = []

    components = bom_value.components or []
    if bom_value.metadata and bom_value.metadata.component:
        components = [bom_value.metadata.component, *components]

    for component in components:
        name = component.name or "unknown"
        version = component.version
        scope = component.scope

        if not component.licenses:
            continue

        for license_choice in component.licenses:
            license_expr = None

            if license_choice.expression:
                license_expr = license_choice.expression
            elif license_choice.license and license_choice.license.id:
                license_expr = license_choice.license.id

            if not license_expr:
                continue

            parse_failed = False
            if license_choice.expression:
                try:
                    atoms = license_expression_atoms(license_expr)
                except ValueError:
                    parse_failed = True
                    atoms = {license_expr}
            else:
                atoms = {license_expr}
            got_warning = False
            got_error = False
            any_unknown = parse_failed
            for atom in atoms:
                folded = atom.casefold()
                if folded in constants.licenses.CATEGORY_A_LICENSES_FOLD:
                    continue
                if folded in constants.licenses.CATEGORY_B_LICENSES_FOLD:
                    got_warning = True
                    continue
                if folded in constants.licenses.CATEGORY_X_LICENSES_FOLD:
                    got_error = True
                    continue
                got_error = True
                any_unknown = True
            if got_error:
                errors.append(
                    models.licenses.Issue(
                        component_name=name,
                        component_version=version,
                        license_expression=license_expr,
                        category=models.licenses.Category.X,
                        any_unknown=any_unknown,
                        scope=scope,
                    )
                )
            elif got_warning:
                warnings.append(
                    models.licenses.Issue(
                        component_name=name,
                        component_version=version,
                        license_expression=license_expr,
                        category=models.licenses.Category.B,
                        any_unknown=False,
                        scope=scope,
                    )
                )

    return warnings, errors
