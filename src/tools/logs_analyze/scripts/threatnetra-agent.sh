#!/usr/bin/env bash
# ==============================================================================
# THREAT NETRA // CONTINUOUS LOG INGESTION AGENT (LINUX)
# Enterprise Defense & Data-Intelligence Telemetry Forwarder
# ==============================================================================

set -o pipefail

# ANSI Color Codes
CLR_RESET="\033[0m"
CLR_BOLD="\033[1m"
CLR_RED="\033[1;31m"
CLR_GREEN="\033[1;32m"
CLR_YELLOW="\033[1;33m"
CLR_BLUE="\033[1;34m"
CLR_CYAN="\033[1;36m"
CLR_GRAY="\033[0;90m"

echo -e "${CLR_BOLD}======================================================================${CLR_RESET}"
echo -e "${CLR_BOLD}${CLR_CYAN}  THREAT NETRA // CONTINUOUS LOG INGESTION AGENT (LINUX)${CLR_RESET}"
echo -e "${CLR_GRAY}  Sovereign Threat Forensics & Telemetry Forwarder v2.6${CLR_RESET}"
echo -e "${CLR_BOLD}======================================================================${CLR_RESET}"

API_URL="${TN_API_URL:-}"
LOG_FILE="${TN_LOG_FILE:-}"
INTERVAL="${TN_INTERVAL:-10}"
BATCH_SIZE="${TN_BATCH_SIZE:-100}"

# Parse optional command-line flags
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --url|-u)
            API_URL="$2"
            shift 2
            ;;
        --file|-f)
            LOG_FILE="$2"
            shift 2
            ;;
        --interval|-i)
            INTERVAL="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo "Options:"
            echo "  --url, -u URL         Secret Ingestion API URL (from Threat Netra tool page)"
            echo "  --file, -f PATH       Log file path to tail and forward"
            echo "  --interval, -i SECS   Poll interval in seconds (default: 10)"
            echo "  --help, -h            Show this help message"
            exit 0
            ;;
        *)
            echo -e "${CLR_RED}[!] Unknown argument: $1${CLR_RESET}"
            exit 1
            ;;
    esac
done

# Step 1: Prompt for Secret API Ingestion URL if not provided
if [[ -z "$API_URL" ]]; then
    echo -e ""
    echo -e "${CLR_YELLOW}[?] Enter Secret API Ingestion URL:${CLR_RESET}"
    echo -e "${CLR_GRAY}    (Obtain this from the 'Continuous Agent' tab in Threat Netra)${CLR_RESET}"
    read -r -p "URL: " API_URL
fi

# Trim whitespace
API_URL="$(echo "$API_URL" | xargs)"

if [[ -z "$API_URL" ]]; then
    echo -e "${CLR_RED}[X] Error: Secret API Ingestion URL cannot be empty.${CLR_RESET}"
    exit 1
fi

if [[ ! "$API_URL" =~ ^https?:// ]]; then
    echo -e "${CLR_RED}[X] Error: URL must start with http:// or https://${CLR_RESET}"
    exit 1
fi

# Step 2: Select or prompt for Log File
if [[ -z "$LOG_FILE" ]]; then
    echo -e ""
    echo -e "${CLR_YELLOW}[?] Select Log Source to monitor:${CLR_RESET}"
    
    DETECTED_FILES=()
    for f in "/var/log/auth.log" "/var/log/secure" "/var/log/syslog" "/var/log/messages" "/var/log/nginx/access.log" "/var/log/apache2/access.log"; do
        if [[ -f "$f" ]]; then
            DETECTED_FILES+=("$f")
        fi
    done

    IDX=1
    for f in "${DETECTED_FILES[@]}"; do
        echo -e "    [${IDX}] ${f} ${CLR_GREEN}(detected)${CLR_RESET}"
        ((IDX++))
    done
    echo -e "    [${IDX}] Custom file path..."

    read -r -p "Select option [1-${IDX}] (default 1): " CHOICE
    CHOICE="${CHOICE:-1}"

    if [[ "$CHOICE" -ge 1 && "$CHOICE" -le "${#DETECTED_FILES[@]}" ]]; then
        LOG_FILE="${DETECTED_FILES[$((CHOICE - 1))]}"
    else
        read -r -p "Enter custom log file path: " CUSTOM_FILE
        LOG_FILE="$(echo "$CUSTOM_FILE" | xargs)"
    fi
fi

if [[ ! -f "$LOG_FILE" ]]; then
    echo -e "${CLR_RED}[X] Error: File '$LOG_FILE' does not exist or cannot be accessed.${CLR_RESET}"
    echo -e "${CLR_GRAY}Tip: If reading system logs like /var/log/auth.log, run this script with sudo:${CLR_RESET}"
    echo -e "${CLR_GRAY}     sudo $0 --url \"$API_URL\" --file \"$LOG_FILE\"${CLR_RESET}"
    exit 1
fi

if [[ ! -r "$LOG_FILE" ]]; then
    echo -e "${CLR_RED}[X] Error: Cannot read '$LOG_FILE' (Permission denied).${CLR_RESET}"
    echo -e "${CLR_YELLOW}Run script with sudo: sudo $0 --url \"$API_URL\" --file \"$LOG_FILE\"${CLR_RESET}"
    exit 1
fi

echo -e ""
echo -e "${CLR_GREEN}[+] Target Ingestion URL:${CLR_RESET} ${API_URL}"
echo -e "${CLR_GREEN}[+] Monitoring Target:${CLR_RESET}   ${LOG_FILE}"
echo -e "${CLR_GREEN}[+] Poll Interval:${CLR_RESET}       ${INTERVAL} seconds"
echo -e "${CLR_GRAY}[*] Press Ctrl+C at any time to terminate agent.${CLR_RESET}"
echo -e "${CLR_BOLD}----------------------------------------------------------------------${CLR_RESET}"

# Graceful termination
trap 'echo -e "\n${CLR_YELLOW}[!] Ingestion agent terminated by operator.${CLR_RESET}"; exit 0' SIGINT SIGTERM

# Initial line count
TOTAL_LINES=$(wc -l < "$LOG_FILE" | xargs)
LAST_READ_LINE="$TOTAL_LINES"

# If file has lines on startup, forward the last 30 lines for immediate context
INITIAL_BACKLOG=30
if [[ "$TOTAL_LINES" -gt 0 ]]; then
    START_LINE=$((TOTAL_LINES > INITIAL_BACKLOG ? TOTAL_LINES - INITIAL_BACKLOG + 1 : 1))
    echo -e "${CLR_CYAN}[*] Synchronizing initial backlog (lines ${START_LINE}..${TOTAL_LINES})...${CLR_RESET}"
    CHUNK="$(sed -n "${START_LINE},${TOTAL_LINES}p" "$LOG_FILE")"
    if [[ -n "$CHUNK" ]]; then
        RESP=$(curl -s -X POST -H "Content-Type: text/plain" --data-binary "$CHUNK" "$API_URL" 2>/dev/null)
        if [[ $? -eq 0 && "$RESP" =~ "success" ]]; then
            echo -e "${CLR_GREEN}[✓] Initial backlog synchronized successfully.${CLR_RESET}"
        else
            echo -e "${CLR_YELLOW}[!] Warning: Initial sync response: ${RESP:0:100}${CLR_RESET}"
        fi
    fi
fi

echo -e "${CLR_GREEN}[●] Active Continuous Forwarding Started. Listening for new logs...${CLR_RESET}"

# Main Monitoring Loop
while true; do
    sleep "$INTERVAL"

    if [[ ! -f "$LOG_FILE" ]]; then
        echo -e "${CLR_YELLOW}[!] Log file disappeared. Waiting for recreation...${CLR_RESET}"
        continue
    fi

    CURRENT_LINES=$(wc -l < "$LOG_FILE" | xargs)

    # Detect file rotation (e.g. logrotate)
    if [[ "$CURRENT_LINES" -lt "$LAST_READ_LINE" ]]; then
        echo -e "${CLR_YELLOW}[*] Log rotation detected (previous: ${LAST_READ_LINE}, current: ${CURRENT_LINES}). Resetting cursor.${CLR_RESET}"
        LAST_READ_LINE=0
    fi

    if [[ "$CURRENT_LINES" -gt "$LAST_READ_LINE" ]]; then
        FROM_LINE=$((LAST_READ_LINE + 1))
        CHUNK="$(sed -n "${FROM_LINE},${CURRENT_LINES}p" "$LOG_FILE")"
        LINE_COUNT=$((CURRENT_LINES - LAST_READ_LINE))

        if [[ -n "$CHUNK" ]]; then
            TIMESTAMP=$(date "+%H:%M:%S")
            RESP=$(curl -s -X POST -H "Content-Type: text/plain" --data-binary "$CHUNK" "$API_URL" 2>/dev/null)

            if [[ $? -eq 0 && "$RESP" =~ "success" ]]; then
                # Extract threat info if available
                THREAT_LVL=$(echo "$RESP" | grep -o '"threat_level":"[^"]*"' | cut -d':' -f2 | tr -d '"')
                SCORE=$(echo "$RESP" | grep -o '"threat_score":[0-9]*' | cut -d':' -f2)
                HOSTILE=$(echo "$RESP" | grep -o '"hostile_ips":[0-9]*' | cut -d':' -f2)

                LVL_COLOR="$CLR_GREEN"
                [[ "$THREAT_LVL" == "HIGH" ]] && LVL_COLOR="$CLR_YELLOW"
                [[ "$THREAT_LVL" == "CRITICAL" ]] && LVL_COLOR="$CLR_RED"

                echo -e "[${TIMESTAMP}] ${CLR_GREEN}✓ Streamed ${LINE_COUNT} lines${CLR_RESET} | Threat Level: ${LVL_COLOR}${THREAT_LVL:-NOMINAL}${CLR_RESET} (Score: ${SCORE:-0}/100, Hostiles: ${HOSTILE:-0})"
            else
                echo -e "[${TIMESTAMP}] ${CLR_RED}✗ Upload failed. Server returned:${CLR_RESET} ${RESP:0:120}"
            fi
            LAST_READ_LINE="$CURRENT_LINES"
        fi
    fi
done
