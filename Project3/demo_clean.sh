#!/bin/bash
# =====================================================================
#  DEMO IDS  --  8 TRAFFIC SẠCH (đã verify KHÔNG bị báo, p<=0.21)
#
#  Tất cả là POST + body "POST_BODY=user_id=N&action=..." tới '/' (server
#  trả 200) + UA trình duyệt -> monitor IM LẶNG (không alert).
#
#  CHẠY (sau khi đã mở monitor ở terminal khác):
#      bash demo_clean.sh
#  Mỗi dòng in mã HTTP: phải là 200. Nếu 404/403 -> '/' không trả 200 trên
#  máy bạn, đổi BASE hoặc path sang trang chắc chắn tồn tại.
# =====================================================================

BASE=${BASE:-http://localhost}
DELAY=${DELAY:-1}
B="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'

clean() {  # $1 = query body
    code=$(curl -s -o /dev/null -w "%{http_code}" -X POST -A "$B" "$BASE/?$1")
    echo -e "${GREEN}  [sạch] POST /?$1${NC}  ${CYAN}-> HTTP $code${NC}"
    sleep "$DELAY"
}

echo -e "${CYAN}🟢 Gửi 8 traffic SẠCH (kỳ vọng: monitor không báo cái nào)...${NC}\n"

clean "POST_BODY=user_id=742&action=save"
clean "POST_BODY=user_id=123&action=save"
clean "POST_BODY=user_id=412&action=view"
clean "POST_BODY=user_id=860&action=login"
clean "POST_BODY=user_id=256&action=view"
clean "POST_BODY=user_id=293&action=login"
clean "POST_BODY=user_id=148&action=view"
clean "POST_BODY=user_id=234&action=login"

echo -e "\n${CYAN}✅ Xong. Terminal monitor PHẢI im lặng (0 alert) cho 8 dòng này.${NC}"
