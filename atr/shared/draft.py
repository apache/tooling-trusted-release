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

import atr.forms as forms


class DeleteFileForm(forms.Typed):
    """Form for deleting a file."""

    file_path = forms.string("File path")
    submit = forms.submit("Delete file")


class DeleteForm(forms.Typed):
    """Form for deleting a candidate draft."""

    release_name = forms.hidden()
    project_name = forms.hidden()
    version_name = forms.hidden()
    confirm_delete = forms.string("Confirmation", validators=forms.constant("DELETE"))
    submit = forms.submit("Delete candidate draft")
