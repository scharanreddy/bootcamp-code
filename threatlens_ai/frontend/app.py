import streamlit as st


def main() -> None:
    """Streamlit app entrypoint."""
    st.set_page_config(page_title="ThreatLens AI", layout="wide")
    st.title("ThreatLens AI")
    st.markdown("This workspace contains the Streamlit frontend scaffold for ThreatLens AI.")
    st.info("Business logic and UI flow are placeholders.")


if __name__ == "__main__":
    main()
