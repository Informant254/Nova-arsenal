"""Nova-Arsenal LLM Module"""

from nova_arsenal.llm.base import LLMProvider

__all__ = ["LLMProvider", "LLMRouter", "get_llm_router", "MultiProviderRouter"]


def __getattr__(name):
    if name == "LLMRouter":
        from nova_arsenal.llm.router import LLMRouter
        return LLMRouter
    elif name == "get_llm_router":
        from nova_arsenal.llm.router import get_llm_router
        return get_llm_router
    elif name == "MultiProviderRouter":
        from nova_arsenal.llm.multi_router import MultiProviderRouter
        return MultiProviderRouter
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
