from __future__ import annotations

import hmac
import logging
import os
from datetime import date, datetime
from typing import Any

import pandas as pd
import streamlit as st
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from src.grc_dashboard.exporting import control_frame as _control_frame
from src.grc_dashboard.exporting import controls_csv
from src.grc_dashboard.intelligence import (
    ADVISORIES_URL,
    KEV_URL,
    ThreatFeedUnavailable,
    fetch_cisa_advisories,
    fetch_kev_catalog,
)
from src.grc_dashboard.risk_engine import (
    compute_overall_score,
    inherent_risk_band,
    inherent_risk_score,
    map_controls_by_framework,
    prioritize_controls,
    suggested_next_step,
    summarize_risk_register,
)
from src.grc_dashboard.security import ROLES, can_edit_controls, can_manage_users
from src.grc_dashboard.store import (
    CONTROL_STATUSES,
    RISK_LEVELS,
    add_workspace_member,
    authenticate_user,
    change_password,
    create_group,
    create_initial_admin,
    create_organization,
    create_user,
    delete_control,
    get_control,
    get_engine,
    initialize_database,
    list_audit_events,
    list_control_history,
    list_controls,
    list_group_members,
    list_groups,
    list_threat_triage,
    list_user_organizations,
    list_users,
    reset_user_password,
    save_control,
    set_group_members,
    update_threat_triage,
    update_user,
    user_count,
    users,
)

st.set_page_config(
    page_title="Northstar | Cyber GRC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

logger = logging.getLogger(__name__)

st.markdown(
    """
    <style>
    :root {
        --ink: #172b4d;
        --muted: #52647a;
        --paper: #f5f8fc;
        --panel: #ffffff;
        --line: #dbe4ef;
        --teal: #087e8b;
        --teal-soft: #e6f5f5;
        --green: #247a56;
        --amber: #a85c00;
        --red: #b42332;
    }
    .stApp { background: var(--paper); color: var(--ink); }
    .block-container { padding-top: 1.5rem; padding-bottom: 2.5rem; }
    h1, h2, h3 { color: var(--ink); letter-spacing: -0.025em; }
    [data-testid="stMetric"] {
        background: var(--panel); border: 1px solid var(--line);
        border-radius: 14px; padding: 1rem 1.1rem;
        box-shadow: 0 4px 14px rgba(23, 43, 77, .04);
    }
    [data-testid="stMetricLabel"] { color: var(--muted); }
    div[data-testid="stSidebar"] {
        background: #142b49; border-right: 1px solid #203f64;
    }
    div[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p,
    div[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] strong,
    div[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] h1,
    div[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] h2,
    div[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] h3,
    div[data-testid="stSidebar"] label,
    div[data-testid="stSidebar"] [data-testid="stWidgetLabel"] p {
        color: #edf5fb;
    }
    div[data-testid="stSidebar"] [data-testid="stRadio"] label {
        background: transparent; border-radius: 10px; padding: .35rem .5rem;
    }
    div[data-testid="stSidebar"] [data-testid="stRadio"] label:hover {
        background: #214664;
    }
    div[data-testid="stSidebar"] input,
    div[data-testid="stSidebar"] [data-baseweb="select"] > div {
        background-color: #203c59; border-color: #31516e; color: #fff;
    }
    div[data-testid="stSidebar"] hr { border-color: #31516e; }
    div[data-testid="stDataFrame"] { border: 1px solid var(--line); border-radius: 12px; }
    .brand-strip {
        border-radius: 16px; padding: 1.15rem 1.4rem; margin-bottom: 1.15rem;
        background: linear-gradient(115deg, #132b4c 0%, #087e8b 100%);
        color: #fff; box-shadow: 0 8px 24px rgba(19, 43, 76, .16);
    }
    .brand-strip p { color: #e7f5f8; margin: .25rem 0 0; }
    .brand-strip strong { font-size: 1.35rem; letter-spacing: .01em; }
    .role-pill {
        display: inline-block; padding: .25rem .65rem; border-radius: 999px;
        background: #e6f5f5; color: #075c66; font-size: .78rem; font-weight: 700;
    }
    .topbar {
        display: flex; align-items: center; justify-content: space-between;
        background: #fff; border: 1px solid var(--line); border-radius: 14px;
        padding: .55rem 1rem; margin-bottom: 1rem;
        box-shadow: 0 4px 14px rgba(23, 43, 77, .04);
    }
    .eyebrow {
        color: var(--muted); font-size: .76rem; font-weight: 700;
        letter-spacing: .09em; text-transform: uppercase;
    }
    .section-card {
        background: #fff; border: 1px solid var(--line);
        border-radius: 14px; padding: 1rem 1.2rem;
    }
    @media (max-width: 700px) {
        .block-container { padding-left: 1rem; padding-right: 1rem; }
    }
    </style>
    """,
    unsafe_allow_html=True,
)


def _notify(message: str, kind: str = "success") -> None:
    st.session_state["flash_message"] = message
    st.session_state["flash_kind"] = kind
    st.rerun()


def _show_flash() -> None:
    message = st.session_state.pop("flash_message", None)
    kind = st.session_state.pop("flash_kind", "success")
    if message:
        getattr(st, kind)(message)


def _database_setup() -> None:
    try:
        initialize_database()
    except (SQLAlchemyError, ValueError):
        logger.exception("Database initialization failed")
        st.error(
            "The database could not be initialized. Check DATABASE_URL and the application logs."
        )
        st.stop()


def _first_admin_setup() -> None:
    st.markdown(
        "<div class='brand-strip'><strong>Northstar · Cyber GRC</strong>"
        "<p>Secure first-time workspace setup</p></div>",
        unsafe_allow_html=True,
    )
    st.title("Create the first administrator")
    st.write(
        "Starter controls are ready. To prevent an unclaimed public workspace, "
        "first-time setup requires the bootstrap token configured by the operator."
    )
    bootstrap_token = os.environ.get("BOOTSTRAP_ADMIN_TOKEN", "")
    if len(bootstrap_token) < 32:
        st.error("Setup is locked. Configure BOOTSTRAP_ADMIN_TOKEN with at least 32 characters.")
        st.stop()
    with st.form("initial_admin", clear_on_submit=True):
        organization_name = st.text_input("Organization / workspace name")
        username = st.text_input("Username")
        display_name = st.text_input("Display name")
        password = st.text_input("Password (12+ characters)", type="password", max_chars=1024)
        confirmation = st.text_input("Confirm password", type="password", max_chars=1024)
        supplied_token = st.text_input("Bootstrap token", type="password", max_chars=1024)
        submitted = st.form_submit_button("Create administrator", type="primary")
    if not submitted:
        return
    if not hmac.compare_digest(supplied_token, bootstrap_token):
        st.error("Bootstrap token is incorrect.")
        return
    if password != confirmation:
        st.error("The passwords do not match.")
        return
    try:
        create_initial_admin(
            username,
            display_name,
            password,
            organization_name=organization_name or "Northstar Workspace",
        )
    except ValueError as error:
        st.error(str(error))
    except SQLAlchemyError:
        st.error("Administrator setup failed. Check the application logs.")
    else:
        _notify("Administrator account created. Sign in to continue.")


def _login() -> None:
    st.markdown(
        "<div class='brand-strip'><strong>Northstar · Cyber GRC</strong>"
        "<p>Governance, risk, controls, and evidence in one workspace</p></div>",
        unsafe_allow_html=True,
    )
    st.title("Sign in")
    _show_flash()
    with st.form("login", clear_on_submit=True):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password", max_chars=1024)
        submitted = st.form_submit_button("Sign in", type="primary")
    if not submitted:
        return
    try:
        user = authenticate_user(username, password)
    except SQLAlchemyError:
        st.error("Sign-in is temporarily unavailable. Check the application logs.")
        return
    if user is None:
        st.error("Username or password is incorrect, or the account is inactive.")
        return
    st.session_state["user"] = user
    st.rerun()


def _required_password_change(user: dict[str, Any]) -> None:
    st.markdown(
        "<div class='brand-strip'><strong>Northstar · Cyber GRC</strong>"
        "<p>Account security</p></div>",
        unsafe_allow_html=True,
    )
    st.title("Set your personal password")
    st.info("A password change is required before you can use the workspace.")
    with st.form("required_password_change", clear_on_submit=True):
        current_password = st.text_input("Temporary password", type="password", max_chars=1024)
        new_password = st.text_input(
            "New password (12+ characters)",
            type="password",
            max_chars=1024,
        )
        confirmation = st.text_input("Confirm new password", type="password", max_chars=1024)
        submitted = st.form_submit_button("Update password", type="primary")
    if submitted:
        if new_password != confirmation:
            st.error("The passwords do not match.")
            return
        try:
            change_password(
                user["id"],
                current_password,
                new_password,
                organization_id=user["organization_id"],
            )
        except ValueError as error:
            st.error(str(error))
        except SQLAlchemyError:
            st.error("Password update failed. Check the application logs.")
        else:
            st.session_state.pop("user", None)
            _notify("Password updated. Sign in again with your new password.")
    if st.button("Sign out", key="required_password_sign_out"):
        st.session_state.pop("user", None)
        st.rerun()


def _current_user() -> dict[str, Any] | None:
    session_user = st.session_state.get("user")
    if not session_user:
        return None
    try:
        with get_engine().connect() as connection:
            row = (
                connection.execute(
                    select(
                        users.c.id,
                        users.c.username,
                        users.c.display_name,
                        users.c.role,
                        users.c.is_active,
                        users.c.must_change_password,
                        users.c.auth_version,
                    ).where(users.c.id == session_user["id"])
                )
                .mappings()
                .first()
            )
    except SQLAlchemyError:
        st.error("Your session could not be verified against the account store.")
        st.stop()
    if (
        row is None
        or not row["is_active"]
        or row["auth_version"] != session_user.get("auth_version")
    ):
        st.session_state.pop("user", None)
        return None
    user = dict(row)
    try:
        workspaces = list_user_organizations(user["id"], user["username"])
    except SQLAlchemyError:
        st.error("Workspace membership could not be verified. Check the application logs.")
        st.stop()
    except ValueError:
        st.session_state.pop("user", None)
        st.session_state.pop("organization_id", None)
        return None
    if not workspaces:
        st.error("Your account does not belong to an active workspace. Contact an administrator.")
        st.stop()
    organization_id = st.session_state.get("organization_id")
    active_workspace = next(
        (item for item in workspaces if item["id"] == organization_id),
        workspaces[0],
    )
    st.session_state["organization_id"] = active_workspace["id"]
    user.update(
        organization_id=active_workspace["id"],
        organization_name=active_workspace["name"],
        role=active_workspace["role"],
    )
    st.session_state["user"] = user
    return user


def _sidebar_navigation(user: dict[str, Any]) -> str:
    pages = ["Overview", "Controls & risk", "Evidence & actions", "Threat intelligence"]
    if can_manage_users(user["role"]):
        pages.append("Workspace & access")
    if st.session_state.get("active_page") not in pages:
        st.session_state["active_page"] = pages[0]
    nav_icons = {
        "Overview": "▦",
        "Controls & risk": "☷",
        "Evidence & actions": "✓",
        "Threat intelligence": "◈",
        "Workspace & access": "⚙",
    }
    with st.sidebar:
        st.markdown(
            "<div style='padding:.4rem .2rem 1.2rem'>"
            "<div style='font-size:1.55rem'>🛡️ <b>NORTHSTAR</b></div>"
            "<div style='margin-left:2.45rem;color:#aec3d6;font-size:.72rem;"
            "letter-spacing:.18em'>CYBER GRC</div></div>",
            unsafe_allow_html=True,
        )
        st.caption("WORKSPACE")
        selected = st.radio(
            "Navigate",
            pages,
            key="active_page",
            format_func=lambda page: f"{nav_icons[page]}   {page}",
            label_visibility="collapsed",
        )
        st.divider()
        st.caption("ACTIVE ORGANIZATION")
        st.markdown(f"**{user['organization_name']}**")
        st.markdown(
            f"<span class='role-pill'>{user['role'].title()}</span>",
            unsafe_allow_html=True,
        )
        if selected in ("Overview", "Controls & risk", "Evidence & actions"):
            st.divider()
            st.caption("REGISTER FILTERS")
            if st.button("Clear all filters", use_container_width=True):
                for key in ("filter_search", "filter_framework", "filter_domain", "filter_risk"):
                    st.session_state.pop(key, None)
                st.rerun()
    return selected


def _workspace_topbar(user: dict[str, Any]) -> None:
    try:
        workspaces = list_user_organizations(user["id"], user["username"])
    except SQLAlchemyError:
        st.error("Workspaces could not be loaded. Check the application logs.")
        st.stop()
    columns = st.columns([5.5, 2.5, 1.8])
    with columns[0]:
        st.markdown("<div class='eyebrow'>Security program workspace</div>", unsafe_allow_html=True)
        st.markdown("## Cybersecurity GRC")
    with columns[1]:
        selected = st.selectbox(
            "Organization",
            [item["id"] for item in workspaces],
            index=next(
                index
                for index, item in enumerate(workspaces)
                if item["id"] == user["organization_id"]
            ),
            format_func=lambda org_id: next(
                item["name"] for item in workspaces if item["id"] == org_id
            ),
            disabled=len(workspaces) <= 1,
            key="workspace_picker",
        )
        if selected != user["organization_id"]:
            st.session_state["organization_id"] = selected
            for key in ("filter_search", "filter_framework", "filter_domain", "filter_risk"):
                st.session_state.pop(key, None)
            st.rerun()
    with columns[2]:
        with st.popover(
            f"{user['display_name']} · {user['role'].title()}", use_container_width=True
        ):
            st.markdown(f"**{user['username']}**")
            st.caption(f"Signed in · {datetime.now().astimezone():%a, %d %b %Y %H:%M}")
            with st.form("change_password", clear_on_submit=True):
                current_password = st.text_input("Current password", type="password")
                new_password = st.text_input(
                    "New password (12+ characters)", type="password", max_chars=1024
                )
                confirmation = st.text_input(
                    "Confirm new password", type="password", max_chars=1024
                )
                submitted = st.form_submit_button("Change password")
            if submitted:
                if new_password != confirmation:
                    st.error("The passwords do not match.")
                else:
                    try:
                        change_password(
                            user["id"],
                            current_password,
                            new_password,
                            organization_id=user["organization_id"],
                        )
                    except ValueError as error:
                        st.error(str(error))
                    except SQLAlchemyError:
                        st.error("Password update failed. Check the application logs.")
                    else:
                        st.session_state.pop("user", None)
                        _notify("Password updated. Sign in again.")
            if st.button("Sign out", use_container_width=True):
                st.session_state.pop("user", None)
                st.session_state.pop("organization_id", None)
                st.rerun()


def _filtered_controls(all_controls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    frameworks = sorted({item["framework"] for item in all_controls})
    domains = sorted({item["domain"] for item in all_controls})
    with st.sidebar:
        st.divider()
        st.markdown("### Register filters")
        search = st.text_input(
            "Search controls",
            placeholder="ID, control, or owner",
            key="filter_search",
        )
        framework = st.selectbox("Framework", ["All", *frameworks], key="filter_framework")
        domain = st.selectbox("Domain", ["All", *domains], key="filter_domain")
        risk = st.selectbox("Residual risk", ["All", *RISK_LEVELS], key="filter_risk")
    filtered = all_controls
    if framework != "All":
        filtered = [item for item in filtered if item["framework"] == framework]
    if domain != "All":
        filtered = [item for item in filtered if item["domain"] == domain]
    if risk != "All":
        filtered = [item for item in filtered if item["risk_level"] == risk]
    query = search.strip().casefold()
    if query:
        filtered = [
            item
            for item in filtered
            if query
            in " ".join(str(item[field]) for field in ("id", "control", "owner")).casefold()
        ]
    return filtered


def _overview(
    items: list[dict[str, Any]],
    organization_id: int,
    actor: str,
    role: str,
) -> None:
    summary = summarize_risk_register(items)
    score = compute_overall_score(items)
    now = datetime.now().astimezone()
    due_soon = [
        item
        for item in items
        if item["due_date"]
        and item["due_date"] < date.today().isoformat()
        and item["status"] != "Implemented"
    ]
    open_controls = [item for item in items if item["status"] != "Implemented"]
    high_inherent = [
        item
        for item in items
        if inherent_risk_band(inherent_risk_score(item)) in ("High", "Critical")
    ]
    kpis = st.columns(5)
    kpis[0].metric(
        "Maturity score",
        f"{score:.1f}%",
        help="Average recorded maturity across the current filtered controls.",
    )
    kpis[1].metric("Controls in scope", summary["total"])
    kpis[2].metric("Open actions", len(open_controls))
    kpis[3].metric("High inherent risk", len(high_inherent))
    kpis[4].metric("Overdue", len(due_soon))
    st.caption(
        f"Portfolio snapshot · refreshed {now:%d %b %Y, %H:%M %Z} · "
        f"{len(open_controls) / summary['total'] * 100:.0f}% of controls need follow-up"
        if summary["total"]
        else f"Portfolio snapshot · refreshed {now:%d %b %Y, %H:%M %Z}"
    )
    st.subheader("Risk posture")
    risk_cols = st.columns(4)
    for column, label in zip(risk_cols, ("Low", "Moderate", "High", "Critical")):
        column.metric(label, summary[label.lower()])
    if not items:
        st.info("No controls match these filters. Adjust the filters or add a control.")
        return
    left, right = st.columns([1.2, 1])
    with left:
        st.subheader("Maturity by domain")
        domain_scores = (
            pd.DataFrame(items)
            .groupby("domain", as_index=False)["status_score"]
            .mean()
            .rename(columns={"status_score": "Average maturity"})
            .set_index("domain")
        )
        st.bar_chart(domain_scores, y="Average maturity", color="#087e8b")
    with right:
        st.subheader("Controls by framework")
        framework_counts = map_controls_by_framework(items)
        framework_chart = pd.DataFrame(
            [
                {"Framework": framework, "Controls": count}
                for framework, count in framework_counts.items()
            ]
        ).set_index("Framework")
        st.bar_chart(framework_chart, color="#51aeb0")

    left, right = st.columns(2)
    with left:
        st.subheader("Residual risk distribution")
        risk_chart = pd.DataFrame(
            [
                {"Residual risk": label, "Controls": summary[label.lower()]}
                for label in ("Low", "Moderate", "High", "Critical")
            ]
        ).set_index("Residual risk")
        st.bar_chart(risk_chart, color="#b65a4d")
    with right:
        st.subheader("Remediation due dates")
        open_due = [item for item in items if item["due_date"] and item["status"] != "Implemented"]
        if open_due:
            due_chart = (
                pd.DataFrame(open_due)
                .assign(due_date=lambda frame: pd.to_datetime(frame["due_date"]))
                .groupby("due_date", as_index=False)
                .size()
                .rename(columns={"size": "Open actions"})
                .set_index("due_date")
            )
            st.bar_chart(due_chart, color="#d49348")
        else:
            st.info("No open remediation actions in the current view.")

    st.subheader("Risk assessment")
    st.caption(
        "Inherent risk is an analyst-entered 1–5 likelihood × 1–5 impact estimate. "
        "It is not an actuarial probability, validated forecast, or internet-derived score."
    )
    risk_assessment = pd.DataFrame(
        [
            {
                "Control ID": item["id"],
                "Control": item["control"],
                "Likelihood": item["likelihood"],
                "Impact": item["impact"],
                "Inherent score": inherent_risk_score(item),
                "Inherent band": inherent_risk_band(inherent_risk_score(item)),
                "Residual rating": item["risk_level"],
                "Maturity": f"{item['status_score']}%",
            }
            for item in items
        ]
    )
    st.dataframe(risk_assessment, hide_index=True, use_container_width=True)
    st.subheader("Highest-priority controls")
    ranked = prioritize_controls(items)[:5]
    focus = []
    controls_by_id = {item["id"]: item for item in items}
    for item in ranked:
        source = controls_by_id[item["id"]]
        focus.append(
            {
                "Priority": item["priority_score"],
                "Control": item["control"],
                "Residual risk": item["risk_level"],
                "Inherent score": f"{item['inherent_risk_score']}/25",
                "Maturity": f"{item['status_score']}%",
                "Owner": item["owner"],
                "Due date": source["due_date"],
                "Suggested next step": suggested_next_step(source),
                "Last updated": source["updated_at"],
            }
        )
    st.dataframe(pd.DataFrame(focus), hide_index=True, use_container_width=True)
    if due_soon:
        st.warning(f"{len(due_soon)} control(s) are overdue and not marked implemented.")
        st.dataframe(_control_frame(due_soon), hide_index=True, use_container_width=True)
    try:
        history = list_control_history(organization_id, actor)
    except SQLAlchemyError:
        st.error("Control change history could not be loaded. Check the application logs.")
        return
    if role == "administrator" and history:
        history_frame = pd.DataFrame(history).sort_values("recorded_at")
        st.subheader("Recorded maturity updates")
        st.caption(
            "Each point is a control create/edit event, not a daily organization-wide snapshot."
        )
        chart = history_frame.set_index("recorded_at")[["status_score"]]
        st.line_chart(chart, color="#087e8b")


def _control_form(items: list[dict[str, Any]], actor: str, organization_id: int) -> None:
    if not can_edit_controls(st.session_state["user"]["role"]):
        st.info("Your viewer role allows read-only access to the control register.")
        return
    modes = ["Add control", "Edit control"]
    if can_manage_users(st.session_state["user"]["role"]):
        modes.append("Delete control")
    mode = st.radio("Control action", modes, horizontal=True)
    if mode == "Add control":
        selected: dict[str, Any] = {
            "id": "",
            "control": "",
            "domain": "Governance",
            "framework": "NIST CSF 2.0",
            "owner": "",
            "status": "Not started",
            "status_score": 0,
            "likelihood": 3,
            "impact": 3,
            "risk_level": "Moderate",
            "due_date": date.today(),
            "evidence": "",
            "note": "",
        }
        creating = True
    elif not items:
        st.info("There are no controls available to edit.")
        return
    else:
        selected_id = st.selectbox(
            "Select control",
            [item["id"] for item in items],
            key="edit_control_selection",
        )
        try:
            selected = get_control(selected_id, organization_id=organization_id, actor=actor)
        except SQLAlchemyError:
            st.error("Could not load this control. Check the application logs.")
            return
        if selected is None:
            st.warning("That control has been removed. Refresh the register.")
            return
        creating = False
    if mode == "Delete control":
        with st.form(f"delete_control_{selected['id']}"):
            st.warning(f"This permanently removes {selected['id']} from the register.")
            confirmation = st.text_input(f"Type {selected['id']} to confirm")
            submitted = st.form_submit_button("Delete control", type="primary")
        if submitted:
            if confirmation.strip().upper() != selected["id"]:
                st.error("The confirmation ID does not match.")
            else:
                try:
                    delete_control(selected["id"], actor, organization_id=organization_id)
                except ValueError as error:
                    st.error(str(error))
                except SQLAlchemyError:
                    st.error("Control deletion failed. Check the application logs.")
                else:
                    _notify(f"Control {selected['id']} deleted.")
        return
    with st.form(f"control_form_{mode}_{selected['id'] or 'new'}"):
        col_a, col_b = st.columns(2)
        with col_a:
            identifier = st.text_input("Control ID", value=selected["id"], disabled=not creating)
            name = st.text_input("Control name", value=selected["control"])
            domain = st.text_input("Domain", value=selected["domain"])
            framework = st.text_input("Framework", value=selected["framework"])
            owner = st.text_input("Owner", value=selected["owner"])
            status = st.selectbox(
                "Implementation status",
                CONTROL_STATUSES,
                index=CONTROL_STATUSES.index(selected["status"]),
            )
        with col_b:
            status_score = st.number_input(
                "Maturity score (0-100)",
                min_value=0,
                max_value=100,
                value=int(selected["status_score"]),
            )
            likelihood = st.number_input(
                "Likelihood (1 rare – 5 almost certain)",
                min_value=1,
                max_value=5,
                value=int(selected["likelihood"]),
                help="Analyst estimate for this organization; not a probability forecast.",
            )
            impact = st.number_input(
                "Impact (1 minimal – 5 severe)",
                min_value=1,
                max_value=5,
                value=int(selected["impact"]),
                help="Analyst estimate of business impact if the risk occurs.",
            )
            score = int(likelihood) * int(impact)
            st.caption(f"Inherent risk: {score}/25 · {inherent_risk_band(score)}")
            risk_level = st.selectbox(
                "Risk rating",
                RISK_LEVELS,
                index=RISK_LEVELS.index(selected["risk_level"]),
            )
            due_value = selected["due_date"]
            due_date = st.date_input(
                "Remediation due date",
                value=date.fromisoformat(due_value) if isinstance(due_value, str) else due_value,
            )
            evidence = st.text_area(
                "Evidence reference", value=selected["evidence"], max_chars=4000
            )
            note = st.text_area("Notes / remediation", value=selected["note"], max_chars=4000)
        submitted = st.form_submit_button(
            "Save control" if creating else "Save changes",
            type="primary",
        )
    if submitted:
        values = {
            "id": identifier,
            "control": name,
            "domain": domain,
            "framework": framework,
            "owner": owner,
            "status": status,
            "status_score": status_score,
            "likelihood": likelihood,
            "impact": impact,
            "risk_level": risk_level,
            "due_date": due_date.isoformat(),
            "evidence": evidence,
            "note": note,
        }
        try:
            save_control(
                values,
                actor,
                creating=creating,
                organization_id=organization_id,
            )
        except ValueError as error:
            st.error(str(error))
        except SQLAlchemyError:
            st.error(
                "Control save failed. Check for duplicate IDs and review the application logs."
            )
        else:
            _notify(f"Control {values['id'].strip().upper()} saved.")


def _user_admin(actor: str, current_user_id: int, organization_id: int) -> None:
    st.subheader("Members")
    st.caption(
        "Roles are scoped to this organization. Group access can grant viewer or editor, "
        "but never administrator."
    )
    with st.expander("Create an account", expanded=False):
        with st.form("create_user", clear_on_submit=True):
            username = st.text_input("Username", key="new_username")
            display_name = st.text_input("Display name", key="new_display_name")
            role = st.selectbox(
                "Role",
                ROLES,
                index=ROLES.index("viewer"),
                format_func=lambda value: value.title(),
                help=(
                    "Viewer: read/export. Editor: maintain controls. "
                    "Administrator: manage users and all records."
                ),
            )
            password = st.text_input("Temporary password (12+ characters)", type="password")
            submitted = st.form_submit_button("Create account", type="primary")
        if submitted:
            try:
                create_user(
                    username,
                    display_name,
                    password,
                    role,
                    actor,
                    organization_id=organization_id,
                )
            except ValueError as error:
                st.error(str(error))
            except SQLAlchemyError:
                st.error("Account creation failed. The username may already be in use.")
            else:
                _notify(f"Account {username.strip().lower()} created.")
    try:
        users_df = pd.DataFrame(list_users(organization_id=organization_id, actor=actor))
    except (SQLAlchemyError, ValueError):
        st.error("Could not load accounts. Check the application logs.")
        return
    if users_df.empty:
        st.info("No accounts found.")
        return
    st.dataframe(users_df, hide_index=True, use_container_width=True)
    selectable = users_df[users_df["id"] != current_user_id]
    if not selectable.empty:
        with st.expander("Reset a user's password", expanded=False):
            with st.form("reset_user_password", clear_on_submit=True):
                reset_user_id = st.selectbox(
                    "Account",
                    selectable["id"].tolist(),
                    format_func=lambda value: selectable.loc[
                        selectable["id"] == value, "username"
                    ].iloc[0],
                )
                temporary_password = st.text_input(
                    "Temporary password (12+ characters)",
                    type="password",
                    max_chars=1024,
                )
                password_confirmation = st.text_input(
                    "Confirm temporary password",
                    type="password",
                    max_chars=1024,
                )
                reset_submitted = st.form_submit_button("Reset password")
            if reset_submitted:
                if temporary_password != password_confirmation:
                    st.error("The passwords do not match.")
                else:
                    try:
                        reset_user_password(
                            int(reset_user_id),
                            temporary_password,
                            actor,
                            organization_id=organization_id,
                        )
                    except ValueError as error:
                        st.error(str(error))
                    except SQLAlchemyError:
                        st.error("Password reset failed. Check the application logs.")
                    else:
                        _notify(
                            "Password reset. Share the temporary password securely; "
                            "the user must change it at their next sign-in."
                        )
    if selectable.empty:
        st.info("Create another administrator before changing the current account.")
        return
    with st.form("update_user"):
        selected_id = st.selectbox(
            "Account to update",
            selectable["id"].tolist(),
            format_func=lambda value: selectable.loc[selectable["id"] == value, "username"].iloc[0],
        )
        selected_row = users_df.loc[users_df["id"] == selected_id].iloc[0]
        updated_role = st.selectbox(
            "Role",
            ROLES,
            index=ROLES.index(selected_row["direct_role"]),
            format_func=lambda value: value.title(),
        )
        active = st.checkbox("Account active", value=bool(selected_row["is_active"]))
        submitted = st.form_submit_button("Update access")
    if submitted:
        try:
            update_user(
                int(selected_id),
                updated_role,
                active,
                actor,
                organization_id=organization_id,
            )
        except ValueError as error:
            st.error(str(error))
        except SQLAlchemyError:
            st.error("Access update failed. Check the application logs.")
        else:
            _notify("Account permissions updated.")


def _group_admin(actor: str, organization_id: int) -> None:
    st.subheader("Access groups")
    st.caption(
        "Groups make team access easier to manage. A group grants viewer or editor access "
        "within this organization; it can never grant administrator."
    )
    with st.form(f"create_group_{organization_id}", clear_on_submit=True):
        group_name = st.text_input("Group name", placeholder="Security operations")
        group_role = st.selectbox(
            "Group permission",
            ("viewer", "editor"),
            format_func=lambda role: role.title(),
            help=(
                "Editors can create and update controls. "
                "Only direct organization admins can manage users."
            ),
        )
        create_submitted = st.form_submit_button("Create group", type="primary")
    if create_submitted:
        try:
            create_group(group_name, group_role, organization_id, actor)
        except ValueError as error:
            st.error(str(error))
        except SQLAlchemyError:
            st.error("Group creation failed. Check the application logs.")
        else:
            _notify(f"Group {group_name.strip()} created.")
    try:
        members = list_users(organization_id=organization_id, actor=actor)
        available_groups = list_groups(organization_id, actor)
    except (SQLAlchemyError, ValueError):
        st.error("Groups or workspace members could not be loaded.")
        return
    if not available_groups:
        st.info("Create a group to manage team permissions in one place.")
        return
    st.dataframe(pd.DataFrame(available_groups), hide_index=True, use_container_width=True)
    group_ids = [group["id"] for group in available_groups]
    selected_group_id = st.selectbox(
        "Group to manage",
        group_ids,
        format_func=lambda group_id: next(
            f"{group['name']} · {group['role'].title()}"
            for group in available_groups
            if group["id"] == group_id
        ),
    )
    selected_group = next(group for group in available_groups if group["id"] == selected_group_id)
    active_members = [member for member in members if member["is_active"]]
    member_labels = {
        member["id"]: f"{member['display_name']} (@{member['username']})"
        for member in active_members
    }
    try:
        selected_members = list_group_members(selected_group_id, organization_id, actor)
    except ValueError as error:
        st.error(str(error))
        return
    with st.form(f"group_members_{organization_id}_{selected_group_id}"):
        selected_ids = st.multiselect(
            "People in this group",
            options=list(member_labels),
            default=[user_id for user_id in selected_members if user_id in member_labels],
            format_func=lambda user_id: member_labels[user_id],
        )
        update_submitted = st.form_submit_button("Save group membership")
    if update_submitted:
        try:
            set_group_members(
                selected_group_id,
                selected_ids,
                organization_id,
                actor,
            )
        except ValueError as error:
            st.error(str(error))
        except SQLAlchemyError:
            st.error("Group membership update failed. Check the application logs.")
        else:
            _notify(f"Members updated for {selected_group['name']}.")


def _organization_admin(user: dict[str, Any]) -> None:
    st.subheader("Organizations and workspaces")
    st.caption(
        "Each organization has separately scoped controls, memberships, groups, audit events, "
        "and threat triage. Only your listed memberships appear in the workspace switcher."
    )
    with st.form("create_organization", clear_on_submit=True):
        organization_name = st.text_input("New organization name", placeholder="Northstar Research")
        submitted = st.form_submit_button("Create organization", type="primary")
    if submitted:
        try:
            organization_id = create_organization(
                organization_name,
                user["username"],
                user["organization_id"],
            )
        except ValueError as error:
            st.error(str(error))
        except SQLAlchemyError:
            st.error("Organization creation failed. Check the application logs.")
        else:
            st.session_state["organization_id"] = organization_id
            _notify(f"Workspace {organization_name.strip()} created with starter controls.")
    st.markdown("#### Add an existing account to this organization")
    st.caption(
        "The account keeps its password; its access role is independent " "in each organization."
    )
    with st.form(f"add_workspace_member_{user['organization_id']}", clear_on_submit=True):
        username = st.text_input("Existing account username")
        role = st.selectbox(
            "Organization role",
            ROLES,
            index=ROLES.index("viewer"),
            format_func=lambda value: value.title(),
        )
        add_submitted = st.form_submit_button("Add to organization")
    if add_submitted:
        try:
            add_workspace_member(
                username,
                role,
                user["organization_id"],
                user["username"],
            )
        except ValueError as error:
            st.error(str(error))
        except SQLAlchemyError:
            st.error("Workspace membership could not be added. Check the application logs.")
        else:
            _notify(f"Account {username.strip().lower()} added to this organization.")


@st.cache_data(ttl=3600, show_spinner=False)
def _cached_kev_catalog() -> dict[str, Any]:
    return fetch_kev_catalog()


@st.cache_data(ttl=3600, show_spinner=False)
def _cached_cisa_advisories() -> dict[str, Any]:
    return fetch_cisa_advisories()


def _threat_intelligence(
    organization_id: int,
    actor: str,
    role: str,
) -> None:
    st.title("Threat intelligence")
    st.caption(
        "Official public CISA feeds for analyst awareness. Catalog membership does not mean "
        "a vulnerability affects your organization."
    )
    controls = st.columns([1, 4])
    with controls[0]:
        if st.button("Refresh public feeds", type="primary"):
            _cached_kev_catalog.clear()
            _cached_cisa_advisories.clear()
            st.rerun()
    with controls[1]:
        st.caption(
            "Feeds are fetched on demand and cached for up to one hour. Upstream data are "
            "periodic catalogs, not a real-time attack feed."
        )
    try:
        triage = list_threat_triage(organization_id, actor)
    except (SQLAlchemyError, ValueError):
        st.error("Workspace threat triage could not be loaded.")
        triage = []
    triage_by_cve = {item["cve_id"]: item for item in triage}
    try:
        with st.spinner("Fetching the official CISA Known Exploited Vulnerabilities catalog…"):
            catalog = _cached_kev_catalog()
    except ThreatFeedUnavailable as error:
        st.error(f"CISA KEV feed unavailable: {error}")
        st.link_button("Open CISA KEV catalog", KEV_URL)
    else:
        released = catalog["source_released"]
        st.markdown(
            f"### {catalog['source']}",
        )
        metadata_columns = st.columns(4)
        metadata_columns[0].metric("Catalog entries", len(catalog["vulnerabilities"]))
        metadata_columns[1].metric("Catalog version", catalog["catalog_version"])
        metadata_columns[2].metric("Source release date", released)
        metadata_columns[3].metric(
            "Retrieved (UTC)",
            catalog["retrieved_at"].strftime("%d %b %Y · %H:%M"),
        )
        st.caption(
            f"Source: [CISA KEV catalog]({KEV_URL}) · Data retrieved "
            f"{catalog['retrieved_at'].isoformat()} · Confirm applicability in your own "
            "asset inventory before creating remediation work."
        )
        search = st.text_input(
            "Search public catalog",
            placeholder="CVE, vendor, or product",
            key="kev_search",
        ).casefold()
        vulnerabilities = catalog["vulnerabilities"]
        if search:
            vulnerabilities = [
                item
                for item in vulnerabilities
                if search in " ".join(str(value) for value in item.values()).casefold()
            ]
        visible = vulnerabilities[:100]
        kev_frame = pd.DataFrame(visible)
        kev_frame["Workspace triage"] = kev_frame["CVE"].map(
            lambda cve: triage_by_cve.get(cve, {}).get("status", "New")
        )
        st.dataframe(kev_frame, hide_index=True, use_container_width=True)
        if len(vulnerabilities) > len(visible):
            st.caption(
                f"Showing the 100 most recently added matching entries of "
                f"{len(vulnerabilities):,}. Narrow the search to review specific items."
            )
        st.link_button("View official CISA source", KEV_URL)
        if can_edit_controls(role) and visible:
            st.subheader("Workspace triage")
            st.caption(
                "This is an analyst-entered status for this workspace only. It does not "
                "automatically match your asset inventory or confirm exposure."
            )
            cve_id = st.selectbox("CVE to triage", [item["CVE"] for item in visible])
            current_triage = triage_by_cve.get(cve_id, {})
            statuses = ("New", "Reviewing", "Mitigating", "Mitigated", "Not applicable")
            with st.form(f"triage_{organization_id}_{cve_id}"):
                triage_status = st.selectbox(
                    "Triage status",
                    statuses,
                    index=(
                        statuses.index(current_triage["status"])
                        if current_triage.get("status") in statuses
                        else 0
                    ),
                )
                triage_notes = st.text_area(
                    "Analyst notes", value=current_triage.get("notes", ""), max_chars=1000
                )
                submitted = st.form_submit_button("Save triage", type="primary")
            if submitted:
                try:
                    update_threat_triage(
                        cve_id,
                        triage_status,
                        triage_notes,
                        organization_id,
                        actor,
                    )
                except ValueError as error:
                    st.error(str(error))
                except SQLAlchemyError:
                    st.error("Triage update failed. Check the application logs.")
                else:
                    _notify(f"Workspace triage saved for {cve_id}.")

    st.divider()
    st.subheader("CISA cybersecurity advisories")
    try:
        with st.spinner("Checking CISA's public advisory feed…"):
            advisories = _cached_cisa_advisories()
    except ThreatFeedUnavailable as error:
        st.warning(f"CISA advisory feed unavailable: {error}")
        st.link_button("Open CISA advisories", ADVISORIES_URL)
    else:
        st.caption(
            f"{len(advisories['advisories'])} official advisories · retrieved "
            f"{advisories['retrieved_at'].isoformat()} · "
            f"[Source RSS]({ADVISORIES_URL})"
        )
        advisory_frame = pd.DataFrame(advisories["advisories"][:50])
        if not advisory_frame.empty:
            st.dataframe(
                advisory_frame,
                hide_index=True,
                use_container_width=True,
                column_config={
                    "Official advisory": st.column_config.LinkColumn(
                        "Official source", display_text="Open CISA advisory"
                    )
                },
            )


def _evidence_actions(items: list[dict[str, Any]]) -> None:
    st.title("Evidence & actions")
    st.caption(
        "Track follow-up, evidence references, due dates, and the last update for this workspace."
    )
    today = date.today()
    open_items = [item for item in items if item["status"] != "Implemented"]
    overdue = [
        item
        for item in open_items
        if item["due_date"] and date.fromisoformat(item["due_date"]) < today
    ]
    due_next_30 = [
        item
        for item in open_items
        if item["due_date"] and 0 <= (date.fromisoformat(item["due_date"]) - today).days <= 30
    ]
    metrics = st.columns(4)
    metrics[0].metric("Open actions", len(open_items))
    metrics[1].metric("Overdue", len(overdue))
    metrics[2].metric("Due in next 30 days", len(due_next_30))
    metrics[3].metric(
        "Evidence referenced",
        (
            f"{sum(bool(item['evidence']) for item in items) / len(items) * 100:.0f}%"
            if items
            else "0%"
        ),
    )
    st.info(
        "Evidence fields are references only. Store evidence files in your "
        "approved, access-controlled repository."
    )
    rows = [
        {
            "ID": item["id"],
            "Control": item["control"],
            "Owner": item["owner"],
            "Status": item["status"],
            "Residual risk": item["risk_level"],
            "Likelihood × impact": f"{item['likelihood']} × {item['impact']}",
            "Inherent score": f"{inherent_risk_score(item)}/25",
            "Due date": item["due_date"],
            "Evidence reference": item["evidence"],
            "Remediation notes": item["note"],
            "Suggested next step": suggested_next_step(item),
            "Created": item["created_at"],
            "Last updated": item["updated_at"],
        }
        for item in items
    ]
    st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)


def _workspace_administration(user: dict[str, Any]) -> None:
    st.title("Workspace & access")
    st.caption(
        f"Administer members, role-based groups, and organization workspaces · "
        f"Current role: {user['role'].title()}"
    )
    members_tab, groups_tab, organizations_tab, audit_tab = st.tabs(
        ("Members", "Groups", "Organizations", "Audit trail")
    )
    with members_tab:
        _user_admin(user["username"], user["id"], user["organization_id"])
    with groups_tab:
        _group_admin(user["username"], user["organization_id"])
    with organizations_tab:
        _organization_admin(user)
    with audit_tab:
        st.subheader("Recent workspace activity")
        try:
            audit = list_audit_events(
                organization_id=user["organization_id"],
                actor=user["username"],
            )
        except (SQLAlchemyError, ValueError):
            st.error("Workspace audit history could not be loaded.")
        else:
            st.dataframe(pd.DataFrame(audit), hide_index=True, use_container_width=True)


def _main() -> None:
    _database_setup()
    try:
        total_users = user_count()
    except SQLAlchemyError:
        st.error("The account store could not be read. Check the application logs.")
        st.stop()
    if total_users == 0:
        _first_admin_setup()
        return
    user = _current_user()
    if user is None:
        _login()
        return
    if user["must_change_password"]:
        _required_password_change(user)
        return

    page = _sidebar_navigation(user)
    _workspace_topbar(user)
    _show_flash()
    st.caption(
        f"{user['organization_name']} · shared controls, risk decisions, and evidence references"
    )
    controls_all: list[dict[str, Any]] = []
    filtered: list[dict[str, Any]] = []
    if page in ("Overview", "Controls & risk", "Evidence & actions"):
        try:
            controls_all = list_controls(
                organization_id=user["organization_id"],
                actor=user["username"],
            )
        except (SQLAlchemyError, ValueError):
            st.error("The control register could not be loaded for this workspace.")
            st.stop()
        filtered = _filtered_controls(controls_all)
    if page == "Overview":
        _overview(
            filtered,
            user["organization_id"],
            user["username"],
            user["role"],
        )
    elif page == "Controls & risk":
        st.title("Controls & risk")
        st.caption(
            "Every score is organization-entered. Record the rationale and "
            "keep source evidence in its approved repository."
        )
        st.dataframe(_control_frame(filtered), hide_index=True, use_container_width=True)
        st.download_button(
            "Export filtered register (CSV)",
            data=controls_csv(filtered),
            file_name=(
                f"{user['organization_name'].lower().replace(' ', '-')}-controls-"
                f"{datetime.now().date().isoformat()}.csv"
            ),
            mime="text/csv",
        )
        st.divider()
        _control_form(filtered, user["username"], user["organization_id"])
    elif page == "Evidence & actions":
        _evidence_actions(filtered)
    elif page == "Threat intelligence":
        _threat_intelligence(
            user["organization_id"],
            user["username"],
            user["role"],
        )
    elif page == "Workspace & access" and can_manage_users(user["role"]):
        _workspace_administration(user)
    st.caption(
        "Risk and maturity are decision-support indicators, not certification evidence "
        "or legal advice. Threat catalog entries are not evidence of exposure. "
        "Use HTTPS and restrict network access when deploying."
    )


if __name__ == "__main__":
    _main()
