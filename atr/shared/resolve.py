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


class ResolveVoteForm(forms.Typed):
    """Form for resolving a vote."""

    email_body = forms.textarea("Email body", optional=True, rows=24)
    vote_result = forms.radio(
        "Vote result",
        choices=[
            ("passed", "Passed"),
            ("failed", "Failed"),
        ],
    )
    submit = forms.submit("Resolve vote")


class ResolveVoteManualForm(forms.Typed):
    """Form for resolving a vote manually."""

    vote_result = forms.radio(
        "Vote result",
        choices=[
            ("passed", "Passed"),
            ("failed", "Failed"),
        ],
    )
    vote_thread_url = forms.string("Vote thread URL")
    vote_result_url = forms.string("Vote result URL")
    submit = forms.submit("Resolve vote")
