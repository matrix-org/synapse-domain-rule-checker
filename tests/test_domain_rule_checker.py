# Copyright 2021 The Matrix.org Foundation C.I.C.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from typing import Optional

import aiounittest

from synapse.module_api.errors import ConfigError

from synapse_domain_rule_checker import DomainRuleChecker
from tests import create_module


class DomainRuleCheckerTestCase(aiounittest.AsyncTestCase):
    async def _test_user_may_invite(
        self,
        config: dict,
        inviter: str,
        invitee: Optional[str],
        new_room: bool,
        published: bool,
    ) -> bool:
        checker = create_module(config, new_room, published)
        return await checker.user_may_invite(inviter, invitee, "room")

    async def test_allowed(self):
        config = {
            "can_invite_if_not_in_domain_mapping": False,
            "domain_mapping": {
                "source_one": ["target_one", "target_two"],
                "source_two": ["target_two"],
            },
            "domains_prevented_from_being_invited_to_published_rooms": ["target_two"],
        }

        self.assertTrue(
            await self._test_user_may_invite(
                config,
                "test:source_one",
                "test:target_one",
                False,
                False,
            ),
        )

        self.assertTrue(
            await self._test_user_may_invite(
                config,
                "test:source_one",
                "test:target_two",
                False,
                False,
            ),
        )

        self.assertTrue(
            await self._test_user_may_invite(
                config,
                "test:source_two",
                "test:target_two",
                False,
                False,
            ),
        )

        # User can invite internal user to a published room
        self.assertTrue(
            await self._test_user_may_invite(
                config,
                "test:source_one",
                "test1:target_one",
                False,
                True,
            ),
        )

        # User can invite external user to a non-published room
        self.assertTrue(
            await self._test_user_may_invite(
                config,
                "test:source_one",
                "test:target_two",
                False,
                False,
            ),
        )

    async def test_disallowed(self):
        config = {
            "can_invite_if_not_in_domain_mapping": True,
            "domain_mapping": {
                "source_one": ["target_one", "target_two"],
                "source_two": ["target_two"],
                "source_four": [],
            },
        }

        self.assertFalse(
            await self._test_user_may_invite(
                config,
                "test:source_one",
                "test:target_three",
                False,
                False,
            )
        )
        self.assertFalse(
            await self._test_user_may_invite(
                config,
                "test:source_two",
                "test:target_three",
                False,
                False,
            )
        )
        self.assertFalse(
            await self._test_user_may_invite(
                config, "test:source_two", "test:target_one", False, False
            )
        )
        self.assertFalse(
            await self._test_user_may_invite(
                config, "test:source_four", "test:target_one", False, False
            )
        )

        # User cannot invite external user to a published room
        self.assertTrue(
            await self._test_user_may_invite(
                config, "test:source_one", "test:target_two", False, True
            )
        )

    async def test_default_allow(self):
        config = {
            "can_invite_if_not_in_domain_mapping": True,
            "domain_mapping": {
                "source_one": ["target_one", "target_two"],
                "source_two": ["target_two"],
            },
        }

        self.assertTrue(
            await self._test_user_may_invite(
                config,
                "test:source_three",
                "test:target_one",
                False,
                False,
            )
        )

    async def test_default_deny(self):
        config = {
            "can_invite_if_not_in_domain_mapping": False,
            "domain_mapping": {
                "source_one": ["target_one", "target_two"],
                "source_two": ["target_two"],
            },
        }

        self.assertFalse(
            await self._test_user_may_invite(
                config,
                "test:source_three",
                "test:target_one",
                False,
                False,
            )
        )

    def test_config_parse(self):
        config = {
            "can_invite_if_not_in_domain_mapping": False,
            "domain_mapping": {
                "source_one": ["target_one", "target_two"],
                "source_two": ["target_two"],
            },
        }
        parsed_config = DomainRuleChecker.parse_config(config)

        self.assertFalse(parsed_config.can_invite_if_not_in_domain_mapping)
        self.assertEqual(parsed_config.domain_mapping, config["domain_mapping"])

    def test_config_parse_failure(self):
        config = {
            "domain_mapping": {
                "source_one": ["target_one", "target_two"],
                "source_two": ["target_two"],
            }
        }
        self.assertRaises(ConfigError, DomainRuleChecker.parse_config, config)
