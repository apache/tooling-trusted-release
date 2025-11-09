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

import atr.form as form


class StartVotingForm(form.Form):
    mailing_list: str = form.label(
        "Send vote email to",
        "Note: The options to send to the user-tests "
        "mailing list and yourself are provided for "
        "testing purposes only, and will not be "
        "available in the finished version of ATR.",
        widget=form.Widget.RADIO,
    )
    vote_duration: form.Int = form.label(
        "Minimum vote duration",
        "Minimum number of hours the vote will be open for.",
        default=72,
    )
    subject: str = form.label("Subject")
    body: str = form.label("Body", widget=form.Widget.TEXTAREA)
