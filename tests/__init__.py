from typing import Any, Dict, Optional

import attr
from synapse.module_api import StateMap

from synapse_domain_rule_checker import DomainRuleChecker, EventTypes


@attr.s(auto_attribs=True)
class MockEvent:
    """Mock of an event, only implementing the fields the DomainRuleChecker module will
    use.
    """

    sender: str
    membership: Optional[str] = None


@attr.s(auto_attribs=True)
class MockPublicRoomListManager:
    """Mock of a synapse.module_api.PublicRoomListManager, only implementing the method
    the DomainRuleChecker module will use.
    """

    _published: bool

    async def room_is_in_public_room_list(self, room_id: str) -> bool:
        return self._published


@attr.s(auto_attribs=True)
class MockModuleApi:
    """Mock of a synapse.module_api.ModuleApi, only implementing the methods the
    DomainRuleChecker module will use.
    """

    _new_room: bool
    _published: bool

    def register_spam_checker_callbacks(self, *args: Any, **kwargs: Any) -> None:
        """Don't fail when the module tries to register its callbacks."""
        pass

    @property
    def public_room_list_manager(self) -> MockPublicRoomListManager:
        """Returns a mock public room list manager. We could in theory return a Mock with
        a return value of make_awaitable(self._published), but local testing seems to show
        this doesn't work on all versions of Python.
        """
        return MockPublicRoomListManager(self._published)

    async def get_room_state(self, *args: Any, **kwargs: Any) -> StateMap[MockEvent]:
        """Mocks the ModuleApi's get_room_state method, by returning mock events. The
        number of events depends on whether we're testing for a new room or not (if the
        room is not new it will have an extra user joined to it).
        """
        state = {
            (EventTypes.Create, ""): MockEvent("room_creator"),
            (EventTypes.Member, "room_creator"): MockEvent("room_creator", "join"),
            (EventTypes.Member, "invitee"): MockEvent("room_creator", "invite"),
        }

        if not self._new_room:
            state[(EventTypes.Member, "joinee")] = MockEvent("joinee", "join")

        return state


def create_module(
    config_dict: Dict[str, Any], new_room: bool, published: bool
) -> DomainRuleChecker:
    # Create a mock based on the ModuleApi spec, but override some mocked functions
    # because some capabilities are needed for running the tests.
    module_api = MockModuleApi(new_room, published)

    # If necessary, give parse_config some configuration to parse.
    config = DomainRuleChecker.parse_config(config_dict)

    # Tell mypy to ignore that we're giving the module a fake ModuleApi.
    return DomainRuleChecker(config, module_api)  # type: ignore[arg-type]
