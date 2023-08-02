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
from typing import Any, Dict, Optional

import aiounittest
from synapse.module_api.errors import ConfigError

from synapse_domain_rule_checker import DomainRuleChecker
from tests import create_module


class DomainRuleCheckerTestCase(aiounittest.AsyncTestCase):
    async def _test_user_may_invite(
        self,
        config: Dict[str, Any],
        inviter: str,
        invitee: Optional[str],
        new_room: bool,
        published: bool,
        unknown_room: bool = False,
    ) -> bool:
        checker = create_module(config, new_room, published, unknown_room)
        if invitee is None:
            return await checker.user_may_send_3pid_invite(
                inviter, "email", "a@b", "!r"
            )
        else:
            return await checker.user_may_invite(inviter, invitee, "!r")

    async def _test_user_may_join_room(
        self,
        config: Dict[str, Any],
        is_invited: bool,
    ) -> bool:
        checker = create_module(config, False, False, False)
        return await checker.user_may_join_room("@a:b", "!r", is_invited)

    async def test_allowed(self) -> None:
        config = {
            "can_invite_if_not_in_domain_mapping": False,
            "domain_mapping": {
                "source_one": ["target_one", "target_two"],
                "source_two": ["target_two"],
            },
            "domains_prevented_from_being_invited_to_published_rooms": ["target_two"],
        }

        # Check that a user can invite a remote server if the domain mapping allows it.
        self.assertTrue(
            await self._test_user_may_invite(
                config,
                "test:source_one",
                "test:target_one",
                False,
                False,
            ),
        )

        # Check that a user can invite a remote server if the domain mapping allows it.
        self.assertTrue(
            await self._test_user_may_invite(
                config,
                "test:source_one",
                "test:target_two",
                False,
                False,
            ),
        )

        # Check that a user can invite a remote server if the domain mapping allows it.
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

    async def test_allowed_regex(self) -> None:
        config = {
            "can_invite_if_not_in_domain_mapping": False,
            "use_regex": True,
            "domain_mapping": {
                "source_one": ["target_(one|two)"],
                "source_two": [".*_two"],
            },
            "domains_prevented_from_being_invited_to_published_rooms": ["target_two"],
        }

        # Check that a user can invite a remote server if the domain mapping allows it.
        self.assertTrue(
            await self._test_user_may_invite(
                config,
                "test:source_one",
                "test:target_one",
                False,
                False,
            ),
        )

        # Check that a user can invite a remote server if the domain mapping allows it.
        self.assertTrue(
            await self._test_user_may_invite(
                config,
                "test:source_one",
                "test:target_two",
                False,
                False,
            ),
        )

        # Check that a user can invite a remote server if the domain mapping allows it.
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

    async def test_disallowed(self) -> None:
        config = {
            "can_invite_if_not_in_domain_mapping": True,
            "domain_mapping": {
                "source_one": ["target_one", "target_two"],
                "source_two": ["target_two"],
                "source_four": [],
            },
            "domains_prevented_from_being_invited_to_published_rooms": ["target_two"],
        }

        # Check that a user can't invite a remote server if the domain mapping doesn't
        # allow it.
        self.assertFalse(
            await self._test_user_may_invite(
                config,
                "test:source_one",
                "test:target_three",
                False,
                False,
            )
        )

        # Check that a user can't invite a remote server if the domain mapping doesn't
        # allow it.
        self.assertFalse(
            await self._test_user_may_invite(
                config,
                "test:source_two",
                "test:target_three",
                False,
                False,
            )
        )

        # Check that a user can't invite a remote server if the domain mapping doesn't
        # allow it.
        self.assertFalse(
            await self._test_user_may_invite(
                config, "test:source_two", "test:target_one", False, False
            )
        )

        # Check that a user can't invite a remote server if the domain mapping doesn't
        # allow it.
        self.assertFalse(
            await self._test_user_may_invite(
                config, "test:source_four", "test:target_one", False, False
            )
        )

        # User cannot invite external user to a published room
        self.assertFalse(
            await self._test_user_may_invite(
                config, "test:source_one", "test:target_two", False, True
            )
        )

    async def test_disallowed_regex(self) -> None:
        config = {
            "can_invite_if_not_in_domain_mapping": True,
            "use_regex": True,
            "domain_mapping": {
                "source_(one|two)": ["target_two"],
                "source_four": [],
            },
            "domains_prevented_from_being_invited_to_published_rooms": ["target_two"],
        }

        # Check that a user can't invite a remote server if the domain mapping doesn't
        # allow it.
        self.assertFalse(
            await self._test_user_may_invite(
                config,
                "test:source_one",
                "test:target_three",
                False,
                False,
            )
        )

        # Check that a user can't invite a remote server if the domain mapping doesn't
        # allow it.
        self.assertFalse(
            await self._test_user_may_invite(
                config,
                "test:source_two",
                "test:target_three",
                False,
                False,
            )
        )

        # Check that a user can't invite a remote server if the domain mapping doesn't
        # allow it.
        self.assertFalse(
            await self._test_user_may_invite(
                config, "test:source_two", "test:target_one", False, False
            )
        )

        # Check that a user can't invite a remote server if the domain mapping doesn't
        # allow it.
        self.assertFalse(
            await self._test_user_may_invite(
                config, "test:source_four", "test:target_one", False, False
            )
        )

        # User cannot invite external user to a published room
        self.assertFalse(
            await self._test_user_may_invite(
                config, "test:source_one", "test:target_two", False, True
            )
        )

    async def test_default_allow(self) -> None:
        """Tests that invites are allowed even when a server isn't in the domain mapping
        if the config says so.
        """
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

        config["use_regex"] = True
        self.assertTrue(
            await self._test_user_may_invite(
                config,
                "test:source_three",
                "test:target_one",
                False,
                False,
            )
        )

    async def test_default_deny(self) -> None:
        """Tests that invites are denied when a server isn't in the domain mapping if the
        config says so.
        """
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

    async def test_3pid_invite_denied(self) -> None:
        """Tests that 3PID invites are denied if the config says so."""
        config = {
            "can_invite_if_not_in_domain_mapping": False,
            "can_invite_by_third_party_id": False,
        }

        self.assertFalse(
            await self._test_user_may_invite(
                config,
                "test:source_one",
                None,
                False,
                False,
            )
        )

    async def test_3pid_invite_allowed(self) -> None:
        """Tests that 3PID invites are allowed if the config says so."""
        config = {
            "can_invite_if_not_in_domain_mapping": False,
            "can_invite_by_third_party_id": True,
        }

        self.assertTrue(
            await self._test_user_may_invite(
                config,
                "test:source_one",
                None,
                False,
                False,
            )
        )

    async def test_join_room(self) -> None:
        """Tests that the module conditions whether a user is able to join a room based
        on the configuration.
        """
        config = {
            "can_invite_if_not_in_domain_mapping": False,
            "can_only_join_rooms_with_invite": True,
        }

        self.assertTrue(await self._test_user_may_join_room(config, True))
        self.assertFalse(await self._test_user_may_join_room(config, False))

        config["can_only_join_rooms_with_invite"] = False

        self.assertTrue(await self._test_user_may_join_room(config, True))
        self.assertTrue(await self._test_user_may_join_room(config, False))

    def test_config_parse(self) -> None:
        """Tests that a correct configuration passes parse_config."""
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

    def test_config_parse_failure(self) -> None:
        """Tests that a bad configuration doesn't pass parse_config."""
        config = {
            "domain_mapping": {
                "source_one": ["target_one", "target_two"],
                "source_two": ["target_two"],
            }
        }
        self.assertRaises(ConfigError, DomainRuleChecker.parse_config, config)

    async def test_invite_unknown_room(self) -> None:
        """Tests that processing an invite for a room we don't have state for makes the
        module think the room is not new, and therefore rejects the invite if the server
        is only configured to accept invites during room creation.

        It is possible to receive an invite for a room we don't have state for if we've
        received the invite over federation and we're not yet in the room.
        """

        config = {
            "can_invite_if_not_in_domain_mapping": True,
            "can_only_invite_during_room_creation": True,
        }

        self.assertFalse(
            await self._test_user_may_invite(
                config,
                "@test:source_one",
                "@test2:source_one",
                False,
                False,
                unknown_room=True,
            )
        )

    async def test_remote_invite(self) -> None:
        """Tests that we can still receive invite from remote servers even if
        the server is configured to only accept invites during room creation.
        """

        config = {
            "can_invite_if_not_in_domain_mapping": True,
            "can_only_invite_during_room_creation": True,
        }

        self.assertTrue(
            await self._test_user_may_invite(
                config,
                "@test:source_two",
                "@test2:source_one",
                False,
                False,
                unknown_room=True,
            )
        )
