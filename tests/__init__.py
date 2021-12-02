from typing import Any, Dict, Optional

import attr
from mock import Mock
from synapse.module_api import ModuleApi

from synapse_domain_rule_checker import DomainRuleChecker


@attr.s(auto_attribs=True)
class MockEvent:
    """Mocks an event. Only exposes properties the module uses."""
    sender: str
    type: str
    content: Dict[str, Any]
    room_id: str = "!someroom"
    state_key: Optional[str] = None

    def is_state(self) -> bool:
        """Checks if the event is a state event by checking if it has a state key."""
        return self.state_key is not None

    @property
    def membership(self) -> str:
        """Extracts the membership from the event. Should only be called on an event
        that's a membership event, and will raise a KeyError otherwise.
        """
        membership: str = self.content["membership"]
        return membership


def create_module() -> DomainRuleChecker:
    # Create a mock based on the ModuleApi spec, but override some mocked functions
    # because some capabilities are needed for running the tests.
    module_api = Mock(spec=ModuleApi)

    # If necessary, give parse_config some configuration to parse.
    config = DomainRuleChecker.parse_config({})

    return DomainRuleChecker(config, module_api)