from __future__ import annotations

import hmac
import os
from datetime import date, datetime
from typing import Any

import pandas as pd
import streamlit as st
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from src.grc_dashboard.exporting import control_frame as _control_frame
from src.grc_dashboard.exporting import controls_csv
from src.grc_dashboard.risk_engine import (
    compute_overall_score,
    map_controls_by_framework,
    prioritize_controls,
    summarize_risk_register,
)
from src.grc_dashboard.security import ROLES, can_edit_controls, can_manage_users
from src.grc_dashboard.store import (
    CONTROL_STATUSES,
    RISK_LEVELS,
    authenticate_user,
    change_password,
    create_initial_admin,
    create_user,
    delete_control,
    get_control,
    get_engine,
    initialize_database,
    list_audit_events,
    list_controls,
    list_users,
    reset_user_password,
    save_control,
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
    div[data-testid="stSidebar"] { background: #edf3f8; }
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
        create_initial_admin(username, display_name, password)
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
            change_password(user["id"], current_password, new_password)
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
    st.session_state["user"] = user
    return user


def _account_sidebar(user: dict[str, Any]) -> None:
    with st.sidebar:
        st.markdown("### Signed in")
        st.write(f"**{user['display_name']}**")
        st.markdown(
            f"<span class='role-pill'>{user['role'].title()}</span>", unsafe_allow_html=True
        )
        if st.button("Sign out", use_container_width=True):
            st.session_state.pop("user", None)
            st.rerun()
        with st.expander("Change password"):
            with st.form("change_password", clear_on_submit=True):
                current_password = st.text_input("Current password", type="password")
                new_password = st.text_input(
                    "New password (12+ characters)", type="password", max_chars=1024
                )
                confirmation = st.text_input(
                    "Confirm new password", type="password", max_chars=1024
                )
                submitted = st.form_submit_button("Update password")
            if submitted:
                if new_password != confirmation:
                    st.error("The passwords do not match.")
                else:
                    try:
                        change_password(
                            user["id"],
                            current_password,
                            new_password,
                        )
                    except ValueError as error:
                        st.error(str(error))
                    except SQLAlchemyError:
                        st.error("Password update failed. Check the application logs.")
                    else:
                        _notify("Password updated.")


def _filtered_controls(all_controls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    frameworks = sorted({item["framework"] for item in all_controls})
    domains = sorted({item["domain"] for item in all_controls})
    with st.sidebar:
        st.divider()
        st.markdown("### Register filters")
        search = st.text_input("Search controls", placeholder="ID, control, or owner")
        framework = st.selectbox("Framework", ["All", *frameworks])
        domain = st.selectbox("Domain", ["All", *domains])
        risk = st.selectbox("Risk rating", ["All", *RISK_LEVELS])
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


def _overview(items: list[dict[str, Any]]) -> None:
    summary = summarize_risk_register(items)
    score = compute_overall_score(items)
    due_soon = [
        item
        for item in items
        if item["due_date"]
        and item["due_date"] < date.today().isoformat()
        and item["status"] != "Implemented"
    ]
    kpis = st.columns(4)
    kpis[0].metric(
        "Control maturity",
        f"{score:.1f}%",
        help="Average of the selected controls' maturity scores.",
    )
    kpis[1].metric("Controls in view", summary["total"])
    kpis[2].metric("High / critical risks", summary["high"] + summary["critical"])
    kpis[3].metric("Overdue actions", len(due_soon))
    st.subheader("Risk posture")
    risk_cols = st.columns(4)
    for column, label in zip(risk_cols, ("Low", "Moderate", "High", "Critical")):
        column.metric(label, summary[label.lower()])
    if not items:
        st.info("No controls match these filters. Adjust the filters or add a control.")
        return
    left, right = st.columns([1.15, 1])
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
        st.subheader("Framework coverage")
        framework_counts = map_controls_by_framework(items)
        st.dataframe(
            pd.DataFrame(
                [
                    {"Framework": framework, "Controls": count}
                    for framework, count in framework_counts.items()
                ]
            ),
            hide_index=True,
            use_container_width=True,
        )
    st.subheader("Highest-priority controls")
    ranked = prioritize_controls(items)[:5]
    st.dataframe(pd.DataFrame(ranked), hide_index=True, use_container_width=True)
    if due_soon:
        st.warning(f"{len(due_soon)} control(s) are overdue and not marked implemented.")
        st.dataframe(_control_frame(due_soon), hide_index=True, use_container_width=True)


def _control_form(items: list[dict[str, Any]], actor: str) -> None:
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
            selected = get_control(selected_id)
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
                    delete_control(selected["id"], actor)
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
            "risk_level": risk_level,
            "due_date": due_date.isoformat(),
            "evidence": evidence,
            "note": note,
        }
        try:
            save_control(values, actor, creating=creating)
        except ValueError as error:
            st.error(str(error))
        except SQLAlchemyError:
            st.error(
                "Control save failed. Check for duplicate IDs and review the application logs."
            )
        else:
            _notify(f"Control {values['id'].strip().upper()} saved.")


def _user_admin(actor: str, current_user_id: int) -> None:
    st.subheader("User access")
    st.caption("Grant only the permissions each person needs to perform their current work.")
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
                create_user(username, display_name, password, role, actor)
            except ValueError as error:
                st.error(str(error))
            except SQLAlchemyError:
                st.error("Account creation failed. The username may already be in use.")
            else:
                _notify(f"Account {username.strip().lower()} created.")
    try:
        users_df = pd.DataFrame(list_users())
    except SQLAlchemyError:
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
            index=ROLES.index(selected_row["role"]),
            format_func=lambda value: value.title(),
        )
        active = st.checkbox("Account active", value=bool(selected_row["is_active"]))
        submitted = st.form_submit_button("Update access")
    if submitted:
        try:
            update_user(int(selected_id), updated_role, active, actor)
        except ValueError as error:
            st.error(str(error))
        except SQLAlchemyError:
            st.error("Access update failed. Check the application logs.")
        else:
            _notify("Account permissions updated.")


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

    _account_sidebar(user)
    _show_flash()
    st.markdown(
        "<div class='brand-strip'><strong>Northstar · Cyber GRC</strong>"
        "<p>Control assurance · Risk visibility · Evidence accountability</p></div>",
        unsafe_allow_html=True,
    )
    st.title("Cybersecurity GRC workspace")
    st.caption(
        "A shared control register for one organization. Sample starter records are provided "
        "and can be changed or removed."
    )
    try:
        controls_all = list_controls()
    except SQLAlchemyError:
        st.error("The control register could not be loaded. Check the application logs.")
        st.stop()
    filtered = _filtered_controls(controls_all)
    tab_labels = ["Executive overview", "Control register", "Evidence & actions"]
    if can_manage_users(user["role"]):
        tab_labels.append("Users & audit")
    tabs = st.tabs(tab_labels)
    with tabs[0]:
        _overview(filtered)
    with tabs[1]:
        st.subheader("Control register")
        st.dataframe(_control_frame(filtered), hide_index=True, use_container_width=True)
        csv_data = controls_csv(filtered)
        st.download_button(
            "Export filtered register (CSV)",
            data=csv_data,
            file_name=f"grc-controls-{datetime.now().date().isoformat()}.csv",
            mime="text/csv",
        )
        st.divider()
        _control_form(filtered, user["username"])
    with tabs[2]:
        st.subheader("Evidence and remediation")
        st.write(
            "Evidence fields store a reference (for example, a ticket, document ID, or "
            "restricted repository path), not the evidence file itself."
        )
        evidence_rows = [
            {
                "ID": item["id"],
                "Control": item["control"],
                "Owner": item["owner"],
                "Status": item["status"],
                "Risk": item["risk_level"],
                "Due date": item["due_date"],
                "Evidence reference": item["evidence"],
                "Remediation notes": item["note"],
            }
            for item in filtered
        ]
        st.dataframe(pd.DataFrame(evidence_rows), hide_index=True, use_container_width=True)
        if can_edit_controls(user["role"]):
            st.info(
                "Editors and administrators can update evidence references and "
                "remediation notes in the Control register."
            )
    if can_manage_users(user["role"]):
        with tabs[3]:
            _user_admin(user["username"], user["id"])
            st.divider()
            st.subheader("Recent audit events")
            try:
                events_df = pd.DataFrame(list_audit_events())
            except SQLAlchemyError:
                st.error("Audit history could not be loaded. Check the application logs.")
            else:
                st.dataframe(events_df, hide_index=True, use_container_width=True)
    st.caption(
        "Risk and maturity are decision-support indicators, not certification evidence "
        "or legal advice. "
        "Use HTTPS and restrict network access when deploying."
    )


if __name__ == "__main__":
    _main()
