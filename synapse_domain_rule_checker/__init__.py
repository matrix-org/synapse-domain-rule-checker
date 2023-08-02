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

import re
from re import Pattern
from typing import Any, Dict, List, Optional, Set, TypeGuard, cast

import attr
from synapse.module_api import ModuleApi
from synapse.module_api.errors import ConfigError


class EventTypes:
    Create = "m.room.create"
    Member = "m.room.member"


class Membership:
    INVITE = "invite"


@attr.s(auto_attribs=True, frozen=True)
class DomainRuleCheckerConfig:
    can_invite_if_not_in_domain_mapping: bool
    use_regex: bool = False
    domain_mapping: Dict[str, List[str]] = dict()
    can_only_join_rooms_with_invite: bool = False
    can_only_invite_during_room_creation: bool = False
    can_invite_by_third_party_id: bool = True
    domains_prevented_from_being_invited_to_published_rooms: List[str] = []

    def domain_map(self) -> Dict[Pattern[str], Set[Pattern[str]]] | Dict[str, Set[str]]:
        if self.use_regex:
            return {
                re.compile(inviter): {re.compile(invitee) for invitee in invitee_list}
                for inviter, invitee_list in self.domain_mapping.items()
            }

        return {
            inviter: set(invitee_list)
            for inviter, invitee_list in self.domain_mapping.items()
        }

    def prevented_domains(self) -> Set[Pattern[str]] | Set[str]:
        if self.use_regex:
            return {
                re.compile(domain)
                for domain in self.domains_prevented_from_being_invited_to_published_rooms
            }

        return set(self.domains_prevented_from_being_invited_to_published_rooms)


class DomainRuleChecker(object):
    def __init__(self, config: DomainRuleCheckerConfig, api: ModuleApi):
        self._config = config
        self._domain_mapping = config.domain_map()
        self._domains_prevented_from_being_invited_to_published_rooms = (
            config.prevented_domains()
        )
        self._api = api

        self._api.register_spam_checker_callbacks(
            user_may_invite=self.user_may_invite,
            user_may_send_3pid_invite=self.user_may_send_3pid_invite,
            user_may_join_room=self.user_may_join_room,
        )

    async def _is_new_room(self, room_id: str) -> bool:
        """Checks if the room provided looks new according to its state.

        The module will consider a room to look new if the only m.room.member events in
        its state are either for the room's creator (i.e. its join event) or invites sent
        by the room's creator.

        Args:
            room_id: The ID of the room to check.

        Returns:
            Whether the room looks new.
        """
        state_event_filter = [
            (EventTypes.Create, None),
            (EventTypes.Member, None),
        ]

        events = await self._api.get_room_state(room_id, state_event_filter)

        create_event = events.get((EventTypes.Create, ""))
        if create_event is None:
            # If we don't have a create event for this room then it means we're processing
            # an invite we've received over federation, for a room we're not yet in. So
            # we can't pull the data we need to check whether the room is new or not.
            # In this case, we assume the remote homeserver, which knows the state of the
            # room, has done the necessary checks and has vetted this invite.
            return False

        room_creator = create_event.sender

        for key, event in events.items():
            if key[0] == EventTypes.Create:
                continue

            if key[1] != room_creator:
                if (
                    event.sender != room_creator
                    and event.membership != Membership.INVITE
                ):
                    return False

        return True

    async def user_may_invite(
        self,
        inviter_userid: str,
        invitee_userid: str,
        room_id: str,
    ) -> bool:
        """Implements the user_may_invite spam checker callback."""
        return await self._user_may_invite(
            room_id=room_id,
            inviter_userid=inviter_userid,
            invitee_userid=invitee_userid,
        )

    async def user_may_send_3pid_invite(
        self,
        inviter_userid: str,
        medium: str,
        address: str,
        room_id: str,
    ) -> bool:
        """Implements the user_may_send_3pid_invite spam checker callback."""
        return await self._user_may_invite(
            room_id=room_id,
            inviter_userid=inviter_userid,
            invitee_userid=None,
        )

    async def _user_may_invite(
        self,
        room_id: str,
        inviter_userid: str,
        invitee_userid: Optional[str],
    ) -> bool:
        """Processes any incoming invite, both normal Matrix invites and 3PID ones, and
        check if they should be allowed.

        Args:
            room_id: The ID of the room the invite is happening in.
            inviter_userid: The MXID of the user sending the invite.
            invitee_userid: The MXID of the user being invited, or None if this is a 3PID
                invite (in which case no MXID exists for this user yet).

        Returns:
            Whether the invite can be allowed to go through.
        """

        inviter_domain = self._get_domain_from_id(inviter_userid)

        if (
            self._config.can_only_invite_during_room_creation
            # Only check if the room is new for rooms created locally, because we
            # can't reliably figure out whether a remote invite is for a new room.
            and inviter_domain == self._api.server_name
        ):
            # If we can only invite during room creation, check whether this invite is
            # for a room that fits our definition of new.
            if not await self._is_new_room(room_id):
                return False

        # If invitee_userid is None, then this means this is a 3PID invite (without a
        # bound MXID), so we allow it unless the configuration mandates blocking all 3PID
        # invites.
        if invitee_userid is None:
            return self._config.can_invite_by_third_party_id

        invitee_domain = self._get_domain_from_id(invitee_userid)

        published_room = (
            await self._api.public_room_list_manager.room_is_in_public_room_list(
                room_id
            )
        )

        if published_room and self.match_from_domains(
            self._domains_prevented_from_being_invited_to_published_rooms,
            invitee_domain,
        ):
            return False

        return self.is_domain_mapping_passing(inviter_domain, invitee_domain)

    def is_domain_mapping_passing(
        self, inviter_domain: str, invitee_domain: str
    ) -> bool:
        matching_invitees = self.domain_matching_invitees(inviter_domain)
        if matching_invitees is None:
            return self._config.can_invite_if_not_in_domain_mapping

        return self.match_from_domains(matching_invitees, invitee_domain)

    def domain_matching_invitees(
        self, inviter_domain: str
    ) -> Optional[Set[Pattern[str]] | Set[str]]:
        if self.is_string_dict(self._domain_mapping):
            return self._domain_mapping.get(inviter_domain)

        # casting should be totally fine here, at this point, we know that _domain_mapping has to be a regex
        domain_mapping = cast(
            Dict[Pattern[str], Set[Pattern[str]]], self._domain_mapping
        )
        matched = False
        matching: List[Set[Pattern[str]]] = []

        for inviter, invitees in domain_mapping.items():
            if inviter.fullmatch(inviter_domain):
                matched = True
                matching.append(invitees)

        if not matched:
            return None

        return set.union(*matching)

    def match_from_domains(
        self, domains_to_match: Set[Pattern[str]] | Set[str], domain: str
    ) -> bool:
        if not self._config.use_regex:
            return domain in domains_to_match

        for domain_pattern in domains_to_match:
            if domain_pattern.fullmatch(domain):  # type: ignore
                return True

        return False

    async def user_may_join_room(
        self,
        userid: str,
        room_id: str,
        is_invited: bool,
    ) -> bool:
        """Implements the user_may_join_room spam checker callback."""
        if self._config.can_only_join_rooms_with_invite and not is_invited:
            return False

        return True

    def is_string_dict(
        self, container: Dict[Pattern[str], Set[Pattern[str]]] | Dict[str, Set[str]]
    ) -> TypeGuard[Dict[str, Set[str]]]:
        return not self._config.use_regex

    @staticmethod
    def parse_config(config: Dict[str, Any]) -> DomainRuleCheckerConfig:
        """Checks whether required fields exist in the provided configuration for the
        module.
        """
        if "can_invite_if_not_in_domain_mapping" in config:
            return DomainRuleCheckerConfig(**config)
        else:
            raise ConfigError(
                "DomainRuleChecker: can_invite_if_not_in_domain_mapping is required",
            )

    @staticmethod
    def _get_domain_from_id(mxid: str) -> str:
        """Parses a string and returns the domain part of the mxid.

        Args:
           mxid: a valid mxid

        Returns:
           The domain part of the mxid

        """
        idx = mxid.find(":")
        if idx == -1:
            raise Exception("Invalid ID: %r" % (mxid,))
        return mxid[idx + 1 :]
