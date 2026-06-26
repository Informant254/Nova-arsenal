"""Tests for Cursor-inspired Priority Prompt Builder and Tool Definitions."""

import pytest
from nova_arsenal.prompt_builder import (
    Scope, First, Empty, Isolate, Text, ChatMessage, ToolDefinition,
    BASE_PRIORITY, render, PromptBuilder, RenderResult,
    compute_priority_levels, _render_with_level,
    system_message, user_message, assistant_message,
)
from nova_arsenal.tool_definitions import (
    ToolSchema, CURSOR_BUILTIN_TOOLS, NOVA_SECURITY_TOOLS,
    ALL_TOOLS, get_tool_by_name, tools_to_openai_format, tools_to_anthropic_format,
)


class TestPriorityLevels:
    def test_single_scope(self):
        levels = set()
        tree = Scope(priority=0, children=[Text("hello")])
        compute_priority_levels(tree, BASE_PRIORITY, levels)
        assert 0 in levels
        assert len(levels) == 1  # BASE_PRIORITY is added by render() explicitly

    def test_multiple_scopes(self):
        levels = set()
        tree = [
            Scope(priority=0, children=[Text("a")]),
            Scope(priority=-1000, children=[Text("b")]),
            Scope(priority=-5000, children=[Text("c")]),
        ]
        compute_priority_levels(tree, BASE_PRIORITY, levels)
        assert 0 in levels
        assert -1000 in levels
        assert -5000 in levels

    def test_relative_priority(self):
        levels = set()
        tree = Scope(
            relative_priority=-500,
            children=[
                Text("child content"),
            ],
        )
        compute_priority_levels(tree, BASE_PRIORITY, levels)
        expected = BASE_PRIORITY - 500
        assert expected in levels

    def test_absolute_overrides_relative(self):
        levels = set()
        tree = Scope(
            absolute_priority=42,
            relative_priority=-999,
            children=[Text("test")],
        )
        compute_priority_levels(tree, BASE_PRIORITY, levels)
        assert 42 in levels
        assert BASE_PRIORITY - 999 not in levels


class TestRenderWithLevel:
    def test_render_all_included(self):
        tree = [
            Scope(priority=0, children=[Text("core ")]),
            Scope(priority=-1000, children=[Text("extra ")]),
            Scope(priority=-5000, children=[Text("context")]),
        ]
        text, empty, chats, tools = _render_with_level(tree, -10000, None)
        assert text == "core extra context"

    def test_render_cutoff_excludes_low_priority(self):
        tree = [
            Scope(priority=0, children=[Text("core ")]),
            Scope(priority=-1000, children=[Text("extra ")]),
            Scope(priority=-5000, children=[Text("context")]),
        ]
        text, empty, chats, tools = _render_with_level(tree, -500, None)
        # At cutoff -500: priority 0 >= -500 (included),
        # priority -1000 < -500 (excluded), priority -5000 < -500 (excluded)
        assert text == "core "

    def test_render_strict_cutoff(self):
        tree = [
            Scope(priority=0, children=[Text("only_this")]),
            Scope(priority=-100, children=[Text("not_this")]),
        ]
        text, empty, chats, tools = _render_with_level(tree, 0, None)
        assert text == "only_this"

    def test_empty_reserves_tokens(self):
        tree = [Scope(priority=0, children=[Empty(100), Text("hello")])]
        text, empty, chats, tools = _render_with_level(tree, 0, None)
        assert text == "hello"
        assert empty == 100


class TestRender:
    def test_render_fits_all(self):
        tree = [
            Scope(priority=0, children=[Text("hello world")]),
        ]
        text, empty, chats, tools = render(tree, token_limit=1000)
        assert text == "hello world"

    def test_render_trims_low_priority(self):
        tree = [
            Scope(priority=0, children=[Text("A" * 100)]),
            Scope(priority=-1000, children=[Text("B" * 1000)]),
            Scope(priority=-2000, children=[Text("C" * 2000)]),
        ]
        text, empty, chats, tools = render(tree, token_limit=50)
        assert "A" in text
        assert text.count("A") == 100

    def test_first_picks_highest_priority_child(self):
        tree = [
            First([
                Scope(priority=100, children=[Text("best ")]),
                Scope(priority=-100, children=[Text("fallback ")]),
                Scope(priority=-500, children=[Text("last_resort")]),
            ]),
        ]
        text, empty, chats, tools = _render_with_level(tree, 50, None)
        assert text == "best "

    def test_first_falls_through(self):
        tree = [
            First([
                Scope(priority=100, children=[Text("best ")]),
                Scope(priority=-100, children=[Text("fallback ")]),
            ]),
        ]
        text, empty, chats, tools = _render_with_level(tree, 200, None)
        # both priorities < 200, so neither renders; text is None (no output)
        assert text is None


class TestChatMessages:
    def test_system_message(self):
        msg = system_message("You are a helpful assistant.")
        assert msg.role == "system"
        assert msg.content == "You are a helpful assistant."

    def test_user_message(self):
        msg = user_message("Hello")
        assert msg.role == "user"

    def test_assistant_message(self):
        msg = assistant_message("I can help with that.")
        assert msg.role == "assistant"
        assert msg.content == "I can help with that."

    def test_chat_in_scope(self):
        tree = Scope(priority=0, children=[
            system_message("sys"),
            user_message("user"),
        ])
        text, empty, chats, tools = _render_with_level(tree, 0, None)
        assert chats is not None
        assert len(chats) == 2
        assert chats[0].role == "system"
        assert chats[1].role == "user"


class TestPromptBuilder:
    def test_builder_basic(self):
        builder = PromptBuilder(token_limit=4096)
        result = builder.render([
            Scope(priority=0, children=[Text("Hello world")]),
        ])
        assert result.text == "Hello world"
        assert result.token_limit == 4096

    def test_builder_token_count(self):
        builder = PromptBuilder(token_limit=4096)
        result = builder.render([
            Scope(priority=0, children=[Text("Hello world")]),
        ])
        assert result.token_count > 0
        assert result.token_count < 10

    def test_builder_trims_low_priority(self):
        builder = PromptBuilder(token_limit=30)
        # ~4 chars per token → 100 chars ≈ 25 tokens (fits in 30)
        high_text = "X" * 100
        # 500 chars ≈ 125 tokens (too big, pushed over the limit)
        low_text = "M" * 500
        result = builder.render([
            Scope(priority=0, children=[Text(high_text)]),
            Scope(priority=-5000, children=[Text(low_text)]),
        ])
        assert "X" in result.text
        assert result.text.count("X") == 100
        assert "M" not in result.text


class TestToolDefinitions:
    def test_cursor_tools_count(self):
        assert len(CURSOR_BUILTIN_TOOLS) == 19

    def test_nova_tools_count(self):
        assert len(NOVA_SECURITY_TOOLS) >= 10

    def test_all_tools_count(self):
        assert len(ALL_TOOLS) == len(CURSOR_BUILTIN_TOOLS) + len(NOVA_SECURITY_TOOLS)

    def test_get_tool_by_name(self):
        tool = get_tool_by_name("edit")
        assert tool is not None
        assert tool.name == "edit"

    def test_get_tool_by_name_nova(self):
        tool = get_tool_by_name("nmap_scan")
        assert tool is not None
        assert "target" in tool.parameters["properties"]

    def test_get_tool_by_name_missing(self):
        tool = get_tool_by_name("nonexistent_tool")
        assert tool is None

    def test_tools_to_openai_format(self):
        tools = [ToolSchema(name="test_tool", description="A test", parameters={"type": "object", "properties": {}})]
        result = tools_to_openai_format(tools)
        assert len(result) == 1
        assert result[0]["type"] == "function"
        assert result[0]["function"]["name"] == "test_tool"

    def test_tools_to_anthropic_format(self):
        tools = [ToolSchema(name="test_tool", description="A test", parameters={"type": "object", "properties": {}})]
        result = tools_to_anthropic_format(tools)
        assert len(result) == 1
        assert result[0]["name"] == "test_tool"
        assert "input_schema" in result[0]

    def test_cursor_tool_has_schema(self):
        for tool in CURSOR_BUILTIN_TOOLS:
            assert tool.name, f"Tool missing name"
            assert tool.description, f"Tool {tool.name} missing description"
            assert "type" in tool.parameters

    def test_nova_tool_has_schema(self):
        for tool in NOVA_SECURITY_TOOLS:
            assert tool.name, f"Tool missing name"
            assert tool.description, f"Tool {tool.name} missing description"
            assert "type" in tool.parameters

    def test_edit_tool_params(self):
        tool = get_tool_by_name("edit")
        props = tool.parameters["properties"]
        assert "file_path" in props
        assert "old_string" in props
        assert "new_string" in props

    def test_nmap_scan_params(self):
        tool = get_tool_by_name("nmap_scan")
        props = tool.parameters["properties"]
        assert "target" in props
        assert "target" in tool.parameters["required"]

    def test_tool_names_unique(self):
        names = [t.name for t in ALL_TOOLS]
        assert len(names) == len(set(names)), "Duplicate tool names found"


class TestScope:
    def test_scope_priority(self):
        s = Scope(priority=42)
        assert s.absolute_priority == 42

    def test_scope_relative(self):
        s = Scope(relative_priority=-500)
        assert s.relative_priority == -500
        assert s.absolute_priority is None

    def test_scope_name(self):
        s = Scope(priority=0, name="my_section")
        assert s.name == "my_section"

    def test_scope_with_children(self):
        s = Scope(priority=0, children=[Text("a"), Text("b")])
        assert len(s.children) == 2

    def test_scope_defaults(self):
        s = Scope()
        assert s.children == []
        assert s.absolute_priority is None
        assert s.relative_priority is None
        assert s.name is None


class TestIsolate:
    def test_isolate_token_limit(self):
        iso = Isolate(token_limit=100, children=[Text("test")])
        assert iso.token_limit == 100

    def test_isolate_caches(self):
        iso = Isolate(token_limit=100, children=[Text("isolated content")])
        text, empty, chats, tools = render([iso], token_limit=1000)
        assert text == "isolated content"
