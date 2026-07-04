#!/bin/bash
# =====================================================================
#  DEMO IDS  --  10 TRAFFIC SẠCH (đã verify với model MỚI: KHÔNG bị báo)
#
#  Gồm 5 GET (phân trang) + 5 POST (form) tới '/' (server trả 200) + UA
#  trình duyệt -> monitor IM LẶNG (0 alert). Đây là các dạng traffic sạch
#  khớp phân phối huấn luyện đã dọn (single HTTP/1.1).
#
#  CHẠY (sau khi đã mở monitor ở terminal khác):
#      bash demo_clean.sh
#  Mỗi dòng in mã HTTP: phải là 200. Nếu 404/403 -> '/' không trả 200 trên
#  máy bạn, đổi BASE sang một trang chắc chắn tồn tại (trả 200).
# =====================================================================

BASE=${BASE:-http://localhost}
DELAY=${DELAY:-1}
B="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'

req() {  # $1=METHOD  $2=query
    if [ "$1" = "GET" ]; then
        code=$(curl -s -o /dev/null -w "%{http_code}" -A "$B" "$BASE/?$2")
    else
        code=$(curl -s -o /dev/null -w "%{http_code}" -X "$1" -A "$B" "$BASE/?$2")
    fi
    echo -e "${GREEN}  [sạch] $1 /?$2${NC}  ${CYAN}-> HTTP $code${NC}"
    sleep "$DELAY"
}

echo -e "${CYAN}🟢 Gửi 10 traffic SẠCH (5 GET + 5 POST) — kỳ vọng: monitor không báo cái nào...${NC}\n"

req GET  "page=1&limit=10"
req GET  "page=12&limit=10"
req GET  "page=7&limit=20"
req GET  "page=25&limit=10"
req GET  "page=3&limit=10"
req POST "POST_BODY=user_id=742&action=save"
req POST "POST_BODY=user_id=305&action=view"
req POST "POST_BODY=user_id=860&action=save"
req POST "POST_BODY=user_id=412&action=save"
req POST "POST_BODY=user_id=123&action=view"

echo -e "\n${CYAN}✅ Xong. Terminal monitor PHẢI im lặng (0 alert) cho 10 dòng này.${NC}"
