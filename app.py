import streamlit as st
import socket
import pandas as pd
from scanner import scan_target
from report import save_report

st.set_page_config(page_title="Vulnerability Scanner", layout="centered")

st.title("(✿◠‿◠) Vulnerability Scanner")
st.markdown("A simple web-based network vulnerability scanner")

# ==================== INPUT SECTION ====================
st.subheader("(◕‿◕) Scan Configuration")

col1, col2 = st.columns(2)
with col1:
    target = st.text_input("Target (IP or Domain)", value="192.168.1.1")
with col2:
    port_range = st.text_input("Port Range", value="1-500")

do_save_report = st.checkbox("Save report after scan", value=True)

if st.button("(ง •̀_•́)ง Start Scan", type="primary", use_container_width=True):
    if not target:
        st.error("(╥﹏╥) Please enter a target")
    else:
        try:
            ip = socket.gethostbyname(target)
            st.info(f"(✧ω✧) Resolved {target} → {ip}")
        except:
            st.error("(╥﹏╥) Could not resolve the target.")
            st.stop()

        try:
            parts = port_range.split("-")
            if len(parts) != 2:
                raise ValueError
            start_port, end_port = int(parts[0]), int(parts[1])
            if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535 and start_port <= end_port):
                raise ValueError
        except (ValueError, AttributeError):
            st.error("(╥﹏╥) Invalid port range. Use format like 1-500 with valid port numbers (1-65535).")
            st.stop()

        with st.spinner(f"(｡♥‿♥｡) Scanning {ip} on ports {start_port}-{end_port}..."):
            results = scan_target(ip, start_port, end_port)

        if results:
            st.success(f"(ﾉ◕ヮ◕)ﾉ*:･ﾟ✧ Scan completed! Found {len(results)} open port(s).")

            # Results Table
            df = pd.DataFrame(results)
            df_display = df[["port", "level", "risk", "banner"]].copy()
            df_display.columns = ["Port", "Risk Level", "Description", "Banner / Info"]

            def color_risk(val):
                if val == "HIGH":
                    return "background-color: #ffcccc; color: #b30000; font-weight: bold"
                elif val == "LOW":
                    return "background-color: #ccffcc; color: #006600"
                return ""

            styled_df = df_display.style.map(color_risk, subset=["Risk Level"])
            st.dataframe(styled_df, use_container_width=True)

            # Missing Security Headers
            st.subheader("(X_X) Missing Security Headers")
            for r in results:
                if r.get("header_issues"):
                    with st.expander(f"> Port {r['port']}"):
                        for h in r["header_issues"]:
                            st.write(f"• {h}")

            # Dangerous HTTP Methods
            st.subheader("(✖‿✖) Dangerous HTTP Methods")
            for r in results:
                if r.get("http_methods"):
                    methods = r["http_methods"]
                    dangerous = [m for m in methods if "No dangerous" not in m and "Could not" not in m]
                    if dangerous:
                        with st.expander(f"> Port {r['port']} - Dangerous Methods Found"):
                            for m in dangerous:
                                st.error(f"• {m}")
                    else:
                        st.success(f"(◕‿◕) Port {r['port']}: No dangerous methods detected")

            # Server Header Exposure
            st.subheader("(⊙_⊙) Server Header Exposure")
            for r in results:
                if r.get("server_info"):
                    info = r["server_info"]
                    if info.get("exposed"):
                        st.warning(f"(X_X) Port {r['port']} → {info['server']} ({info['risk']})")
                    else:
                        st.success(f"(◕‿◕) Port {r['port']} → Server version hidden")

            # Sensitive Paths
            st.subheader("( ͡° ͜ʖ ͡°) Sensitive Paths Discovered")
            for r in results:
                if r.get("sensitive_paths"):
                    paths = r["sensitive_paths"]
                    found = [p for p in paths if isinstance(p, dict)]
                    if found:
                        with st.expander(f"> Port {r['port']} - Sensitive Paths Found"):
                            for p in found:
                                label = f"• {p['path']} (Status: {p['status']} — {p.get('note', '')})"
                                if p["status"] == 200:
                                    st.error(label)
                                else:
                                    st.warning(label)
                    else:
                        st.success(f"(◕‿◕) Port {r['port']}: No sensitive paths found")

            # SSL/TLS Information
            st.subheader("(✧ω✧) SSL/TLS Information")
            ssl_shown = False
            for r in results:
                if r.get("ssl_info") and "error" not in r["ssl_info"]:
                    ssl_shown = True
                    ssl_data = r["ssl_info"]
                    st.write(f"> Port {r['port']}")
                    st.write(f"  - Issuer: {ssl_data['issuer']}")
                    st.write(f"  - Expires in: {ssl_data['days_until_expiry']} days")
                    st.write(f"  - Status: {ssl_data['status']}")
                    st.divider()
            if not ssl_shown:
                st.info("(｡•́︿•̀｡) No SSL/TLS information available.")

            # Save Report
            if do_save_report:
                saved_name = save_report(target, results)
                st.success(f"(ﾉ◕ヮ◕)ﾉ*:･ﾟ✧ Report saved as {saved_name}.json and {saved_name}.txt")

        else:
            st.info("(｡•́︿•̀｡) No open ports found in the given range.")
