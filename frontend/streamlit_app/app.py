import streamlit as st
import pandas as pd
import datetime
from src.data.packet_features import parse_pcap_to_dataframe
from src.data.clean_cicids import clean_dataframe
from frontend.streamlit_app.components.file_upload import process_uploaded_file

st.set_page_config(
    page_title="Predictive Cyber Defence — Network Telemetry Parser",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom High-End Cyber UI Styling
st.markdown("""
<style>
    .reportview-container {
        background: #0e1117;
    }
    .main-header {
        font-size: 2.2rem;
        font-weight: 700;
        background: -webkit-linear-gradient(45deg, #00f2fe, #4facfe);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.2rem;
    }
    .sub-header {
        color: #94a3b8;
        font-size: 1.05rem;
        margin-bottom: 1.5rem;
    }
    .metric-card {
        background-color: #1e293b;
        border: 1px solid #334155;
        border-radius: 8px;
        padding: 16px;
        text-align: center;
    }
    .metric-val {
        font-size: 1.8rem;
        font-weight: bold;
        color: #38bdf8;
    }
    .metric-lbl {
        font-size: 0.85rem;
        color: #94a3b8;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    .badge-pcap {
        background: #0284c7;
        color: white;
        padding: 4px 10px;
        border-radius: 4px;
        font-weight: bold;
        font-size: 0.85rem;
    }
</style>
""", unsafe_allow_html=True)

st.markdown('<div class="main-header">🛡️ Network Telemetry Ingestion & Tabular Inspector</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">AI World Models for Proactive Cyber Defence — Step 1 Telemetry Parser</div>', unsafe_allow_html=True)

# Sidebar Controls
with st.sidebar:
    st.header("⚙️ Parsing Engine")
    st.info("**Engine:** `dpkt` C-Streaming (Offline, Zero-RAM Buffer)")
    st.markdown("---")
    max_preview = st.number_input(
        "Max Packets / Rows to Preview",
        min_value=1_000,
        max_value=1_000_000,
        value=50_000,
        step=10_000,
        help="Caps preview in UI table for maximum rendering performance."
    )
    st.markdown("---")
    st.markdown("### 📁 Supported Formats")
    st.markdown("- **Packet Captures**: `.pcap`, `.pcapng`, `.cap`")
    st.markdown("- **Flow Telemetry**: `.csv` (CIC-IDS2018 / NetFlow)")

# File Upload Section
uploaded_file = st.file_uploader(
    "Upload Raw PCAP, PCAPNG, or Flow CSV File",
    type=["pcap", "pcapng", "cap", "csv"],
    help="Upload network captures of any size. Handled via stream unpacking."
)

# Demo File quick button
col_demo1, col_demo2 = st.columns([1, 4])
with col_demo1:
    use_sample = st.button("Load Pre-packaged Sample PCAP")

if use_sample:
    sample_path = "data/pcaps_sample/demo_sample.pcap"
    with st.spinner("Streaming & parsing sample PCAP..."):
        df = parse_pcap_to_dataframe(sample_path)
        file_type = "Pre-packaged Demo PCAP"
        st.session_state["parsed_df"] = df
        st.session_state["file_type"] = file_type
        st.session_state["file_name"] = "demo_sample.pcap"

elif uploaded_file is not None:
    with st.spinner(f"Parsing '{uploaded_file.name}' with streaming binary reader..."):
        try:
            df, file_type = process_uploaded_file(uploaded_file, max_preview_packets=max_preview)
            st.session_state["parsed_df"] = df
            st.session_state["file_type"] = file_type
            st.session_state["file_name"] = uploaded_file.name
        except Exception as e:
            st.error(f"Error parsing file: {e}")

# Render Parsed Table & Telemetry Metrics
if "parsed_df" in st.session_state:
    df = st.session_state["parsed_df"]
    file_type = st.session_state.get("file_type", "Unknown")
    file_name = st.session_state.get("file_name", "Uploaded File")

    st.success(f"Successfully Parsed **{file_name}** ({file_type})")

    # Metrics Summary Row
    m1, m2, m3, m4, m5 = st.columns(5)
    
    total_pkts = len(df)
    unique_src = df["src_ip"].nunique() if "src_ip" in df.columns else 0
    unique_dst = df["dst_ip"].nunique() if "dst_ip" in df.columns else 0
    
    tcp_count = len(df[df["protocol"] == 6]) if "protocol" in df.columns else 0
    udp_count = len(df[df["protocol"] == 17]) if "protocol" in df.columns else 0

    with m1:
        st.markdown(f'<div class="metric-card"><div class="metric-val">{total_pkts:,}</div><div class="metric-lbl">Total Records</div></div>', unsafe_allow_html=True)
    with m2:
        st.markdown(f'<div class="metric-card"><div class="metric-val">{unique_src:,}</div><div class="metric-lbl">Unique Sources</div></div>', unsafe_allow_html=True)
    with m3:
        st.markdown(f'<div class="metric-card"><div class="metric-val">{unique_dst:,}</div><div class="metric-lbl">Unique Dest</div></div>', unsafe_allow_html=True)
    with m4:
        st.markdown(f'<div class="metric-card"><div class="metric-val">{tcp_count:,}</div><div class="metric-lbl">TCP Packets</div></div>', unsafe_allow_html=True)
    with m5:
        st.markdown(f'<div class="metric-card"><div class="metric-val">{udp_count:,}</div><div class="metric-lbl">UDP Packets</div></div>', unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Search and Filter Toolbar
    f_col1, f_col2, f_col3 = st.columns([2, 1, 1])
    with f_col1:
        ip_search = st.text_input("🔍 Filter by IP Address (Src or Dst):", placeholder="e.g. 192.168.1.100")
    with f_col2:
        proto_filter = st.selectbox("Protocol", options=["All", "TCP (6)", "UDP (17)", "Other"])
    with f_col3:
        flag_filter = st.selectbox("Flag Filter", options=["All", "SYN only", "ACK only", "FIN only", "RST only"])

    # Apply filters
    filtered_df = df.copy()
    if ip_search:
        search_term = ip_search.strip()
        filtered_df = filtered_df[
            filtered_df["src_ip"].astype(str).str.contains(search_term, case=False) |
            filtered_df["dst_ip"].astype(str).str.contains(search_term, case=False)
        ]

    if proto_filter == "TCP (6)":
        filtered_df = filtered_df[filtered_df["protocol"] == 6]
    elif proto_filter == "UDP (17)":
        filtered_df = filtered_df[filtered_df["protocol"] == 17]

    if "syn" in filtered_df.columns:
        if flag_filter == "SYN only":
            filtered_df = filtered_df[filtered_df["syn"] == 1]
        elif flag_filter == "ACK only":
            filtered_df = filtered_df[filtered_df["ack"] == 1]
        elif flag_filter == "FIN only":
            filtered_df = filtered_df[filtered_df["fin"] == 1]
        elif flag_filter == "RST only":
            filtered_df = filtered_df[filtered_df["rst"] == 1]

    # Data Table Inspector
    st.subheader(f"📊 Tabular Inspector ({len(filtered_df):,} matching rows)")
    st.dataframe(
        filtered_df,
        use_container_width=True,
        height=450
    )

    # Export Buttons
    d_col1, d_col2 = st.columns([1, 4])
    with d_col1:
        csv_data = filtered_df.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="📥 Export Filtered Table as CSV",
            data=csv_data,
            file_name=f"parsed_{file_name}.csv",
            mime="text/csv"
        )
else:
    st.info("💡 Upload a `.pcap` or `.csv` above or click **'Load Pre-packaged Sample PCAP'** to see the parser in action!")
