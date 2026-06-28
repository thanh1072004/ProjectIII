#!/bin/bash
# =====================================================================
#  DEMO IDS 3-TIER  --  CHỈ BẮN 6 TRAFFIC TẤN CÔNG (bằng curl)
#
#  Script chỉ gửi 6 request tấn công vào web server. Apache ghi vào access.log
#  và monitor (chạy ở TERMINAL KHÁC, theo dõi access.log thật) báo 6 alert.
#  Cả 6 đều bị bắt bằng REGEX Tier 1 nên LUÔN báo, không phụ thuộc status server.
#
#  ---- CÁCH CHẠY (2 terminal) ----
#  Terminal 1 (monitor đọc access.log thật):
#      tail -n0 -f /var/log/apache2/access.log | python3 apache_log.py monitor /dev/stdin lof
#  Terminal 2 (bắn tấn công):
#      bash demo_ids.sh
#
#  ---- TRAFFIC SẠCH (làm riêng, KHÔNG để trong script) ----
#  Lưu ý: URL gõ tay trên trình duyệt (GET) gần như LUÔN bị báo (domain-shift).
#  Muốn có traffic SẠCH (không báo) phải POST + body, server trả HTTP 200:
#      B="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
#      curl -s -X POST -A "$B" "http://localhost/?POST_BODY=user_id=742&action=save"
#  (path '/' thường trả 200; nếu 404/403 thì đổi sang trang chắc chắn 200.)
# =====================================================================

BASE=${BASE:-http://localhost}
DELAY=${DELAY:-1}
B="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'

req() {  # $1=mô_tả  $2..=curl args
    echo -e "$1"
    code=$(curl -s -o /dev/null -w "%{http_code}" "${@:2}")
    echo -e "      ${CYAN}-> HTTP $code${NC}"
    sleep "$DELAY"
}

echo -e "${CYAN}🚀 DEMO IDS: bắn 6 traffic TẤN CÔNG vào $BASE${NC}"
echo -e "${CYAN}   (xem 6 alert ở terminal đang chạy monitor trên access.log)${NC}\n"

req "${RED}1. SQL Injection${NC}"               -A "$B" "$BASE/login.php?user=admin'%20OR%20'1'%3D'1"
req "${RED}2. Cross-Site Scripting (XSS)${NC}"  -A "$B" "$BASE/search.php?q=%3Cscript%3Ealert(1)%3C/script%3E"
req "${RED}3. Path Traversal / LFI${NC}"        -A "$B" "$BASE/download.php?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd"
req "${RED}4. Scanner tự động (sqlmap UA)${NC}" -A "sqlmap/1.5.8.6#dev" "$BASE/products.php?id=1"
req "${RED}5. HTTP Method Tampering (PUT)${NC}" -X PUT -A "$B" "$BASE/index.php"
req "${RED}6. Command Injection${NC}"           -A "$B" "$BASE/run.php?cmd=;cat%20/etc/passwd"

echo -e "\n${CYAN}✅ ĐÃ BẮN XONG 6 tấn công. Terminal monitor phải hiện 6 alert (CRITICAL).${NC}"
