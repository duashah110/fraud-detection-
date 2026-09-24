import streamlit as st
import requests
from datetime import datetime

SOLANA_RPC_URL = "https://api.mainnet-beta.solana.com"
ETHEREUM_RPC_URL = "https://ethereum-rpc.publicnode.com"

st.set_page_config(
    page_title="ChainGuard | Fraud Detection",
    page_icon="🛡️",
    layout="centered"
)

st.markdown("""
<style>
.stApp {
    background: radial-gradient(circle at top right, #0f766e, #020617 42%, #111827);
    color: white;
}
.main-card {
    background: rgba(255,255,255,0.09);
    padding: 32px;
    border-radius: 24px;
    border: 1px solid rgba(255,255,255,0.18);
    box-shadow: 0 24px 70px rgba(0,0,0,0.40);
}
.title {
    font-size: 44px;
    font-weight: 900;
    text-align: center;
    background: linear-gradient(90deg, #2dd4bf, #60a5fa, #c084fc);
    -webkit-background-clip: text;
    color: transparent;
}
.subtitle {
    text-align: center;
    color: #dbeafe;
    font-size: 17px;
    line-height: 1.7;
}
.risk-low, .risk-medium, .risk-high {
    padding: 15px;
    border-radius: 16px;
    text-align: center;
    font-size: 24px;
    font-weight: 900;
    margin-bottom: 15px;
}
.risk-low { background: linear-gradient(90deg, #16a34a, #22c55e); }
.risk-medium { background: linear-gradient(90deg, #d97706, #f59e0b); }
.risk-high { background: linear-gradient(90deg, #dc2626, #ef4444); }
.note-box {
    background: rgba(15,23,42,0.85);
    padding: 16px;
    border-radius: 14px;
    border: 1px solid rgba(255,255,255,0.14);
    color: #cbd5e1;
}
</style>
""", unsafe_allow_html=True)


def rpc_call(url, method, params):
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    response = requests.post(url, json=payload, timeout=20)
    response.raise_for_status()
    data = response.json()
    if data.get("error"):
        raise Exception(data["error"].get("message", "RPC error"))
    return data.get("result")


def get_solana_transaction(signature):
    return rpc_call(
        SOLANA_RPC_URL,
        "getTransaction",
        [signature, {"encoding": "json", "maxSupportedTransactionVersion": 0}]
    )


def analyze_solana_risk(tx):
    score = 0
    reasons = []

    meta = tx.get("meta", {})
    transaction = tx.get("transaction", {})
    message = transaction.get("message", {})

    status = "Failed" if meta.get("err") else "Success"

    if status == "Failed":
        score += 30
        reasons.append("Transaction failed, which can be a suspicious sign.")

    fee_lamports = meta.get("fee", 0)
    fee_sol = fee_lamports / 1_000_000_000

    if fee_lamports > 10_000_000:
        score += 15
        reasons.append("High transaction fee detected.")

    accounts = message.get("accountKeys", [])
    account_count = len(accounts)

    if account_count > 15:
        score += 20
        reasons.append("Transaction involves many accounts, so it is more complex.")

    instructions = message.get("instructions", [])
    instruction_count = len(instructions)

    if instruction_count > 5:
        score += 20
        reasons.append("Multiple instructions detected in one transaction.")

    pre_balances = meta.get("preBalances", [])
    post_balances = meta.get("postBalances", [])

    largest_change = 0
    for i in range(min(len(pre_balances), len(post_balances))):
        change = abs(pre_balances[i] - post_balances[i]) / 1_000_000_000
        largest_change = max(largest_change, change)

    if largest_change > 10:
        score += 30
        reasons.append("Large SOL movement detected.")
    elif largest_change > 1:
        score += 15
        reasons.append("Medium SOL movement detected.")

    if not reasons:
        reasons.append("No major suspicious activity found.")

    score = min(score, 100)
    level = "High Risk" if score >= 70 else "Medium Risk" if score >= 40 else "Low Risk"

    return {
        "score": score,
        "level": level,
        "reasons": reasons,
        "status": status,
        "fee": f"{fee_sol:.9f} SOL",
        "largest_change": f"{largest_change:.4f} SOL",
        "accounts": account_count,
        "instructions": instruction_count,
        "slot_or_block": tx.get("slot", "N/A"),
        "time": tx.get("blockTime")
    }


def get_ethereum_transaction(tx_hash):
    tx = rpc_call(ETHEREUM_RPC_URL, "eth_getTransactionByHash", [tx_hash])
    if not tx:
        return None, None
    receipt = rpc_call(ETHEREUM_RPC_URL, "eth_getTransactionReceipt", [tx_hash])
    return tx, receipt


def hex_to_int(value):
    if value in [None, ""]:
        return 0
    return int(value, 16)


def analyze_ethereum_risk(tx, receipt):
    score = 0
    reasons = []

    value_eth = hex_to_int(tx.get("value")) / 1_000_000_000_000_000_000
    gas = hex_to_int(tx.get("gas"))
    gas_price = hex_to_int(tx.get("gasPrice"))
    fee_eth = gas * gas_price / 1_000_000_000_000_000_000
    input_data = tx.get("input", "0x")

    status = "Pending"
    if receipt:
        status = "Success" if receipt.get("status") == "0x1" else "Failed"

    if status == "Failed":
        score += 30
        reasons.append("Ethereum transaction failed, which may indicate risky or unsuccessful activity.")
    elif status == "Pending":
        score += 15
        reasons.append("Transaction is still pending, so final status is not confirmed yet.")

    if value_eth > 50:
        score += 35
        reasons.append("Very large ETH transfer detected.")
    elif value_eth > 5:
        score += 20
        reasons.append("Large ETH transfer detected.")
    elif value_eth > 1:
        score += 10
        reasons.append("Medium ETH transfer detected.")

    if fee_eth > 0.05:
        score += 15
        reasons.append("High gas fee detected.")

    if input_data and input_data != "0x" and len(input_data) > 300:
        score += 20
        reasons.append("Complex smart contract interaction detected.")
    elif input_data and input_data != "0x":
        score += 10
        reasons.append("Smart contract interaction detected.")

    if tx.get("to") is None:
        score += 20
        reasons.append("Contract creation transaction detected.")

    log_count = len(receipt.get("logs", [])) if receipt else 0
    if log_count > 8:
        score += 15
        reasons.append("Many event logs found, so transaction activity is complex.")

    if not reasons:
        reasons.append("No major suspicious activity found.")

    score = min(score, 100)
    level = "High Risk" if score >= 70 else "Medium Risk" if score >= 40 else "Low Risk"

    return {
        "score": score,
        "level": level,
        "reasons": reasons,
        "status": status,
        "fee": f"{fee_eth:.9f} ETH",
        "largest_change": f"{value_eth:.6f} ETH",
        "accounts": 2 if tx.get("to") else 1,
        "instructions": "Contract Call" if input_data and input_data != "0x" else "Simple Transfer",
        "slot_or_block": hex_to_int(tx.get("blockNumber")) if tx.get("blockNumber") else "Pending",
        "from": tx.get("from", "N/A"),
        "to": tx.get("to", "Contract Creation"),
        "logs": log_count
    }


def show_risk_box(risk):
    if risk["level"] == "High Risk":
        st.markdown(f'<div class="risk-high">🚨 {risk["level"]} | Score: {risk["score"]}/100</div>', unsafe_allow_html=True)
    elif risk["level"] == "Medium Risk":
        st.markdown(f'<div class="risk-medium">⚠️ {risk["level"]} | Score: {risk["score"]}/100</div>', unsafe_allow_html=True)
    else:
        st.markdown(f'<div class="risk-low">✅ {risk["level"]} | Score: {risk["score"]}/100</div>', unsafe_allow_html=True)


st.markdown('<div class="main-card">', unsafe_allow_html=True)
st.markdown('<div class="title">ChainGuard</div>', unsafe_allow_html=True)
st.markdown(
    '<p class="subtitle">A one-page blockchain fraud detection system for Solana and Ethereum. Select a blockchain, paste a transaction hash, and the app checks real-time blockchain data to show risk level and transaction details.</p>',
    unsafe_allow_html=True
)
st.markdown("---")

st.subheader("🔎 Search Transaction Hash")
st.write("Choose blockchain network, then type or paste the transaction hash below:")

blockchain = st.selectbox("Select Blockchain", ["Solana", "Ethereum"])
hash_value = st.text_input("Transaction Hash", placeholder="Paste transaction hash here...")

if st.button("Analyze Hash", use_container_width=True):
    if not hash_value.strip():
        st.error("Please enter a transaction hash.")
    else:
        with st.spinner(f"Connecting to {blockchain} blockchain and analyzing transaction..."):
            try:
                if blockchain == "Solana":
                    tx = get_solana_transaction(hash_value.strip())
                    if not tx:
                        st.error("Solana transaction not found. Please check the hash and try again.")
                    else:
                        risk = analyze_solana_risk(tx)
                        st.markdown("---")
                        st.subheader("📋 Hash Details")
                        show_risk_box(risk)

                        col1, col2 = st.columns(2)
                        with col1:
                            st.metric("Blockchain", "Solana")
                            st.metric("Status", risk["status"])
                            st.metric("Fee", risk["fee"])
                            st.metric("Total Accounts", risk["accounts"])
                        with col2:
                            st.metric("Instructions", risk["instructions"])
                            st.metric("Largest Change", risk["largest_change"])
                            st.metric("Slot", risk["slot_or_block"])

                        if risk["time"]:
                            readable_time = datetime.fromtimestamp(risk["time"]).strftime("%Y-%m-%d %H:%M:%S")
                            st.info(f"Block Time: {readable_time}")

                        st.markdown("### Risk Reasons")
                        for reason in risk["reasons"]:
                            st.write("•", reason)

                        st.markdown("### Transaction Hash")
                        st.code(hash_value.strip())

                else:
                    tx, receipt = get_ethereum_transaction(hash_value.strip())
                    if not tx:
                        st.error("Ethereum transaction not found. Please check the hash and try again.")
                    else:
                        risk = analyze_ethereum_risk(tx, receipt)
                        st.markdown("---")
                        st.subheader("📋 Hash Details")
                        show_risk_box(risk)

                        col1, col2 = st.columns(2)
                        with col1:
                            st.metric("Blockchain", "Ethereum")
                            st.metric("Status", risk["status"])
                            st.metric("Fee", risk["fee"])
                            st.metric("Value", risk["largest_change"])
                        with col2:
                            st.metric("Block Number", risk["slot_or_block"])
                            st.metric("Type", risk["instructions"])
                            st.metric("Event Logs", risk["logs"])

                        st.markdown("### Wallet Details")
                        st.write("**From:**", risk["from"])
                        st.write("**To:**", risk["to"])

                        st.markdown("### Risk Reasons")
                        for reason in risk["reasons"]:
                            st.write("•", reason)

                        st.markdown("### Transaction Hash")
                        st.code(hash_value.strip())

            except Exception as e:
                st.error(f"Error while checking transaction: {e}")

st.markdown("---")
st.caption("Made for Blockchain Assignment | Real-time Solana + Ethereum fraud risk checker")
st.markdown('</div>', unsafe_allow_html=True)
