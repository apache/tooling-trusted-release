from enum import Enum, auto
from beartype.typing import Optional

class ActorType(Enum):
    PERSON = auto()
    ORGANIZATION = auto()
    TOOL = auto()

class Actor:
    actor_type: ActorType
    name: str
    email: Optional[str]

    def __init__(self, actor_type: ActorType, name: str, email: Optional[str] = None) -> None: ...

    def to_serialized_string(self) -> str: ...

    def __str__(self) -> str: ...

    @property
    def actor_type(self) -> ActorType: ...
    @actor_type.setter
    def actor_type(self, value: ActorType) -> None: ...

    @property
    def name(self) -> str: ...
    @name.setter
    def name(self, value: str) -> None: ...

    @property
    def email(self) -> Optional[str]: ...
    @email.setter
    def email(self, value: Optional[str]) -> None: ...
