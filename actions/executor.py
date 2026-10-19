"""Executes APPROVED actions. Deliberately outside the agent's reach:
  - not in agent/tool_registry.py, so no model can call it
  - only called by the API's approve endpoint, after the role and separation-of-duties checks
  - re-checks the status itself, so even a bug in the caller can't execute an unapproved action

Enforcement is simulated: it changes Sentinel's own records (users, blocked_ips). In a real deployment each
branch would call the identity provider, firewall or ticketing system, through an MCP server or an API.
"""
from datetime import datetime, timezone

from sqlalchemy import insert, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from db.tables import audit_log, blocked_ips, get_engine, proposed_actions, users


class NotApproved(Exception):
    pass


def execute(action_id: int, approved_by: str) -> str:
    with get_engine().begin() as conn:
        action = conn.execute(select(proposed_actions).where(proposed_actions.c.id == action_id)
                              .with_for_update()).one_or_none()
        if action is None or action.status != "approved":
            raise NotApproved(f"action {action_id} is not approved")
        try:
            result = _apply(conn, action)
            status, event = "executed", "action_executed"
        except Exception as e:  # record the failure; never leave an action silently half-done
            result, status, event = f"failed: {type(e).__name__}: {e}", "failed", "action_failed"
        conn.execute(update(proposed_actions).where(proposed_actions.c.id == action_id).values(
            status=status, executed_at=datetime.now(timezone.utc), execution_result=result))
        conn.execute(insert(audit_log).values(actor=approved_by, event=event, action_id=action_id,
                                              details={"result": result}))
    return result


def _apply(conn, action) -> str:
    if action.action_type == "disable_account":
        conn.execute(update(users).where(users.c.user_name == action.target).values(account_disabled=True))
        return f"account {action.target} disabled"
    if action.action_type == "revoke_badge":
        conn.execute(update(users).where(users.c.user_name == action.target).values(badge_revoked=True))
        return f"badge of {action.target} revoked"
    if action.action_type == "require_mfa":
        conn.execute(update(users).where(users.c.user_name == action.target).values(mfa_required=True))
        return f"MFA required for {action.target}"
    if action.action_type == "block_ip":
        conn.execute(pg_insert(blocked_ips).values(ip=action.target, action_id=action.id).on_conflict_do_nothing())
        return f"IP {action.target} blocked"
    if action.action_type == "open_ticket":
        return f"ticket opened: {action.target}"
    raise ValueError(f"unknown action type {action.action_type}")
