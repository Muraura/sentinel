"""propose_action: the only tool that writes anything, and all it writes is a PROPOSAL.

The agent can recommend "disable l.ortiz". It cannot disable anything: execution lives in actions/executor.py,
which is not in the agent's tool registry and is only called by the approval endpoint after an authorised human
approves. "The agent decides what should happen; the system decides what can happen."
"""
import ipaddress
from typing import Annotated, Literal

from pydantic import BaseModel, Field, validate_call
from sqlalchemy import insert, select

from agent.context import current_investigation, current_requester
from db.tables import audit_log, get_engine, proposed_actions, users
from tools.evidence import EVIDENCE_ID, existing_ids

ActionType = Literal["disable_account", "revoke_badge", "block_ip", "require_mfa", "open_ticket"]
USER_ACTIONS = {"disable_account", "revoke_badge", "require_mfa"}


class Proposal(BaseModel):
    action_id: int
    status: str
    message: str


@validate_call
def propose_action(
    action_type: ActionType,
    target: Annotated[str, Field(min_length=1, max_length=200, description="user name, IP address, or ticket title")],
    justification: Annotated[str, Field(min_length=10, max_length=1000)],
    evidence: Annotated[list[Annotated[str, Field(pattern=rf"^(?:{EVIDENCE_ID})$")]], Field(min_length=1)],
) -> Proposal:
    """Propose a remediation action for a human to approve: disable_account / revoke_badge / require_mfa
    (target = user name), block_ip (target = IP address), open_ticket (target = short title). This does NOT
    execute anything; an authorised person reviews the proposal. Cite the evidence IDs that justify it."""
    if action_type in USER_ACTIONS:
        with get_engine().connect() as conn:
            if conn.execute(select(users.c.user_name).where(users.c.user_name == target)).first() is None:
                raise ValueError(f"no user named {target!r}")
    if action_type == "block_ip":
        ipaddress.ip_address(target)  # raises ValueError for anything that isn't an IP address
    unknown = sorted(set(evidence) - existing_ids(set(evidence)))
    if unknown:
        raise ValueError(f"these evidence IDs do not exist: {', '.join(unknown)}")

    investigation = current_investigation.get()
    with get_engine().begin() as conn:
        existing = conn.execute(select(proposed_actions.c.id).where(
            proposed_actions.c.investigation_id == investigation, proposed_actions.c.action_type == action_type,
            proposed_actions.c.target == target, proposed_actions.c.status == "pending")).first()
        if existing:
            return Proposal(action_id=existing.id, status="pending", message="Already proposed; awaiting approval.")
        action_id = conn.execute(insert(proposed_actions).values(
            investigation_id=investigation, action_type=action_type, target=target, justification=justification,
            evidence=evidence, requested_by=current_requester.get(),
        ).returning(proposed_actions.c.id)).scalar_one()
        conn.execute(insert(audit_log).values(
            actor=f"agent:{investigation}", event="action_proposed", action_id=action_id,
            details={"action_type": action_type, "target": target, "evidence": evidence}))
    return Proposal(action_id=action_id, status="pending",
                    message="Proposal recorded. A human with the approver role must approve it; you cannot execute it.")
