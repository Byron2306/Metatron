import asyncio
from unittest.mock import Mock, patch

from backend.services.token_broker import token_broker
from backend.services.tool_gateway import tool_gateway
from backend.services.mcp_server import (
    mcp_server,
    MCPMessageType,
    MCPToolSchema,
    MCPToolCategory,
)


def reset_tokens():
    token_broker.active_tokens.clear()
    token_broker.revoked_tokens.clear()


def gov(decision="gov-test-001", queue="queue-test-001"):
    return {
        "approved": True,
        "decision_id": decision,
        "queue_id": queue,
        "action_type": "mcp_tool_execution",
    }


def test_token_broker_authority():
    reset_tokens()

    token = token_broker.issue_token(
        principal="service:soar",
        principal_identity="spiffe://seraph/soar",
        action="execute",
        targets=["host:test"],
        tool_id="mcp.test.witness",
        max_uses=1,
        governance_context=gov(),
        audience="mcp_server",
    )

    assert token_broker.validate_token(
        token.token_id,
        "service:soar",
        "spiffe://seraph/soar",
        "execute",
        "host:test",
        audience="mcp_server",
        tool_id="mcp.test.witness",
        consume=False,
    )[0]

    assert not token_broker.validate_token(
        token.token_id,
        "service:soar",
        "spiffe://seraph/evil",
        "execute",
        "host:test",
        consume=False,
    )[0]

    assert token_broker.validate_token(
        token.token_id,
        "service:soar",
        "spiffe://seraph/soar",
        "execute",
        "host:test",
        audience="mcp_server",
        tool_id="mcp.test.witness",
        consume=True,
    )[0]

    assert not token_broker.validate_token(
        token.token_id,
        "service:soar",
        "spiffe://seraph/soar",
        "execute",
        "host:test",
        consume=True,
    )[0]


def test_mcp_capability_membrane():
    async def run():
        reset_tokens()

        calls = {"count": 0}

        async def handler(params):
            calls["count"] += 1
            return {"executed": True}

        tool_id = "mcp.test.authority_regression"

        if tool_id not in mcp_server.tools:
            mcp_server.register_tool(
                MCPToolSchema(
                    tool_id=tool_id,
                    name="Authority Regression Witness",
                    description="Synthetic authority witness",
                    category=MCPToolCategory.SOAR,
                    version="1.0.0",
                    input_schema={"type": "object"},
                    output_schema={"type": "object"},
                    required_trust_state="trusted",
                    required_scopes=["test"],
                    rate_limit=100,
                    timeout_seconds=5,
                    async_capable=True,
                    idempotent=False,
                    audit_level="full",
                    redact_fields=[],
                ),
                handler,
            )
        else:
            mcp_server.register_tool_handler(tool_id, handler)

        principal = "service:soar"
        identity = "spiffe://seraph/soar"
        target = "host:test"

        missing = mcp_server.create_message(
            message_type=MCPMessageType.TOOL_REQUEST,
            source=principal,
            destination=tool_id,
            payload={
                "params": {},
                "principal_identity": identity,
                "action": "execute",
                "target": target,
            },
        )

        response = await mcp_server.handle_message(missing)

        assert response.message_type == MCPMessageType.ERROR
        assert calls["count"] == 0

        token = token_broker.issue_token(
            principal=principal,
            principal_identity=identity,
            action="execute",
            targets=[target],
            tool_id=tool_id,
            max_uses=1,
            governance_context=gov(),
            audience="mcp_server",
        )

        valid = mcp_server.create_message(
            message_type=MCPMessageType.TOOL_REQUEST,
            source=principal,
            destination=tool_id,
            payload={
                "params": {},
                "token_id": token.token_id,
                "principal_identity": identity,
                "action": "execute",
                "target": target,
            },
        )

        response = await mcp_server.handle_message(valid)

        assert response.message_type == MCPMessageType.TOOL_RESPONSE
        assert response.payload["status"] == "success"
        assert calls["count"] == 1

        replay = mcp_server.create_message(
            message_type=MCPMessageType.TOOL_REQUEST,
            source=principal,
            destination=tool_id,
            payload={
                "params": {},
                "token_id": token.token_id,
                "principal_identity": identity,
                "action": "execute",
                "target": target,
            },
        )

        response = await mcp_server.handle_message(replay)

        assert response.message_type == MCPMessageType.ERROR
        assert calls["count"] == 1

    asyncio.run(run())


def test_tool_gateway_final_pep():
    reset_tokens()
    tool_gateway.executions.clear()

    calls = {"count": 0}

    def fake_run(*args, **kwargs):
        calls["count"] += 1
        r = Mock()
        r.returncode = 0
        r.stdout = "ok"
        r.stderr = ""
        return r

    principal = "service:test"
    identity = "spiffe://seraph/test"
    target = "host:test"
    tool_id = "process_list"

    with patch(
        "backend.services.tool_gateway.subprocess.run",
        fake_run,
    ):
        denied = tool_gateway.execute(
            tool_id=tool_id,
            parameters={},
            principal=principal,
            token_id="",
            principal_identity=identity,
            action="execute",
            target=target,
            trust_state="trusted",
        )

        assert denied.status == "denied"
        assert calls["count"] == 0

        token = token_broker.issue_token(
            principal=principal,
            principal_identity=identity,
            action="execute",
            targets=[target],
            tool_id=tool_id,
            max_uses=1,
            governance_context=gov(),
            audience="tool_gateway",
        )

        allowed = tool_gateway.execute(
            tool_id=tool_id,
            parameters={},
            principal=principal,
            token_id=token.token_id,
            principal_identity=identity,
            action="execute",
            target=target,
            trust_state="trusted",
        )

        assert allowed.status == "success"
        assert calls["count"] == 1

        replay = tool_gateway.execute(
            tool_id=tool_id,
            parameters={},
            principal=principal,
            token_id=token.token_id,
            principal_identity=identity,
            action="execute",
            target=target,
            trust_state="trusted",
        )

        assert replay.status == "denied"
        assert calls["count"] == 1


def test_end_to_end_delegation():
    async def run():
        reset_tokens()

        calls = {"count": 0}

        def fake_run(*args, **kwargs):
            calls["count"] += 1
            r = Mock()
            r.returncode = 0
            r.stdout = "synthetic-memory-dump-ok"
            r.stderr = ""
            return r

        principal = "service:soar"
        identity = "spiffe://seraph/soar"
        target = "host:test"
        tool_id = "mcp.forensics.memory_dump"

        parent = token_broker.issue_token(
            principal=principal,
            principal_identity=identity,
            action="execute",
            targets=[target],
            tool_id=tool_id,
            max_uses=1,
            governance_context=gov(
                "gov-e2e-001",
                "queue-e2e-001",
            ),
            audience="mcp_server",
        )

        message = mcp_server.create_message(
            message_type=MCPMessageType.TOOL_REQUEST,
            source=principal,
            destination=tool_id,
            payload={
                "params": {
                    "pid": 4242,
                    "execute": True,
                },
                "token_id": parent.token_id,
                "principal_identity": identity,
                "action": "execute",
                "target": target,
            },
        )

        with patch(
            "backend.services.tool_gateway.subprocess.run",
            fake_run,
        ):
            response = await mcp_server.handle_message(message)

        assert response.message_type == MCPMessageType.TOOL_RESPONSE
        assert response.payload["status"] == "success"
        assert calls["count"] == 1

        assert parent.token_id not in token_broker.active_tokens

        delegated = [
            x
            for x in token_broker.token_admin_audit_log
            if x.get("action") == "delegate"
            and x.get("parent_token_id") == parent.token_id
        ]

        assert len(delegated) == 1

        child_id = delegated[0]["child_token_id"]

        assert child_id not in token_broker.active_tokens

        replay = mcp_server.create_message(
            message_type=MCPMessageType.TOOL_REQUEST,
            source=principal,
            destination=tool_id,
            payload={
                "params": {
                    "pid": 4242,
                    "execute": True,
                },
                "token_id": parent.token_id,
                "principal_identity": identity,
                "action": "execute",
                "target": target,
            },
        )

        before = calls["count"]

        with patch(
            "backend.services.tool_gateway.subprocess.run",
            fake_run,
        ):
            replay_response = await mcp_server.handle_message(replay)

        assert replay_response.message_type == MCPMessageType.ERROR
        assert calls["count"] == before

    asyncio.run(run())


def test_root_mcp_is_compatibility_shim():
    import mcp_server as compat
    from backend.services import mcp_server as canonical

    assert compat.mcp_server is canonical.mcp_server
    assert compat.MCPServer is canonical.MCPServer


def test_mcp_chorus_detects_missing_companions_without_blocking_execution():
    async def run():
        reset_tokens()
        tool_gateway.executions.clear()

        from backend.services.vector_memory import vector_memory

        vector_memory.entries.clear()
        vector_memory.namespace_index.clear()
        vector_memory.case_index.clear()

        calls = {"count": 0}

        def fake_run(*args, **kwargs):
            calls["count"] += 1
            r = Mock()
            r.returncode = 0
            r.stdout = "chorus-regression-ok"
            r.stderr = ""
            return r

        principal = "service:soar"
        identity = "spiffe://seraph/soar"
        target = "host:test"
        tool_id = "mcp.forensics.memory_dump"

        parent = token_broker.issue_token(
            principal=principal,
            principal_identity=identity,
            action="execute",
            targets=[target],
            tool_id=tool_id,
            max_uses=1,
            governance_context={
                "approved": True,
                "decision_id": "gov-chorus-regression",
                "queue_id": "queue-chorus-regression",
                "action_type": "mcp_tool_execution",
            },
            audience="mcp_server",
        )

        message = mcp_server.create_message(
            message_type=MCPMessageType.TOOL_REQUEST,
            source=principal,
            destination=tool_id,
            payload={
                "params": {
                    "pid": 4242,
                    "execute": True,
                },
                "token_id": parent.token_id,
                "principal_identity": identity,
                "action": "execute",
                "target": target,
                "policy_decision_id":
                    "gov-chorus-regression",
            },
        )

        with patch(
            "backend.services.tool_gateway.subprocess.run",
            fake_run,
        ):
            response = await mcp_server.handle_message(
                message
            )

        assert response.payload["status"] == "success"
        assert calls["count"] == 1

        execution = mcp_server.executions[
            response.payload["execution_id"]
        ]

        assert execution.chorus_state
        assert execution.edge_observation
        assert execution.chorus_event_id

        chorus = execution.chorus_state
        observation = execution.edge_observation

        assert execution.chorus_resolution_class == "strained"

        assert "dispatch" in observation[
            "observed_participants"
        ]
        assert "executor" in observation[
            "observed_participants"
        ]
        assert "audit_closure" in observation[
            "observed_participants"
        ]

        assert "outbound_gate" in observation[
            "missing_participants"
        ]
        assert "policy_bind" in observation[
            "missing_participants"
        ]

        # Technical success and distributed coherence are
        # deliberately independent properties.
        assert execution.status == "success"
        assert chorus["audit_closure_score"] == 1.0
        assert chorus["companion_presence_score"] < 1.0

        memory = vector_memory.get_entry(
            execution.vector_memory_entry_id
        )

        assert memory is not None
        assert (
            memory.structured_data[
                "chorus_resolution_class"
            ]
            == "strained"
        )

    asyncio.run(run())
