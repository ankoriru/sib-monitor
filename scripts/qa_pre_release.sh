#!/usr/bin/env bash
# QA перед релизом sib-monitor: обязательный шлюз перед push в main.
# Запуск из корня репозитория: bash scripts/qa_pre_release.sh
# Код выхода 0 — релиз можно отправлять; иначе — список FAIL.
set -u
cd "$(dirname "$0")/.."

fail=0; warn=0
ok()   { echo "[OK]   $1"; }
bad()  { echo "[FAIL] $1"; fail=$((fail+1)); }
note() { echo "[WARN] $1"; warn=$((warn+1)); }

# QA-1. Синтаксис всех модулей.
if python3 -m py_compile ./*.py scripts/*.py tests/*.py 2>/tmp/qa_compile.log; then
  ok "QA-1 синтаксис Python"
else
  bad "QA-1 синтаксис Python: $(head -3 /tmp/qa_compile.log)"
fi

# QA-2. Полный набор автотестов. Ограничения по времени и памяти: зависший или
# бесконечный цикл (например, в фоновом воркере) должен падать, а не вешать машину.
if (ulimit -v 6000000; PYTHONPATH=.:tests timeout 300 python3 -m unittest discover -s tests \
      >/tmp/qa_tests.log 2>&1); then
  ok "QA-2 автотесты: $(grep -E '^Ran ' /tmp/qa_tests.log)"
else
  bad "QA-2 автотесты: $(grep -E '^(FAIL|ERROR|Ran|FAILED)' /tmp/qa_tests.log | head -8 | tr '\n' ' ')"
fi

# QA-3. Тесты не должны ходить в сеть: прямые вызовы внешних API запрещены.
if grep -nE "api\.globalping\.io|requests\.(get|post)\(\"https?://|urlopen\(\"https?://" tests/*.py \
     | grep -v "^tests/.*#" >/tmp/qa_net.log; then
  bad "QA-3 сетевые вызовы в тестах: $(head -3 /tmp/qa_net.log)"
else
  ok "QA-3 тесты без сетевых вызовов"
fi

# QA-4. Версия поднята относительно main и совпадает в документации.
ver=$(sed -nE 's/^APP_VERSION = "([^"]+)"/\1/p' app.py)
git fetch -q origin main 2>/dev/null
prev=$(git show origin/main:app.py 2>/dev/null | sed -nE 's/^APP_VERSION = "([^"]+)"/\1/p')
if [ -n "$(git diff --name-only origin/main -- '*.py' requirements.txt Dockerfile certs 2>/dev/null)" ] \
   && [ "$ver" = "$prev" ]; then
  bad "QA-4 код изменён, но APP_VERSION не поднята ($ver)"
else
  ok "QA-4 версия $ver (в main: ${prev:-нет})"
fi
# QA-4a. Документация релиза: версия в описании функционала и запись в CHANGELOG.
grep -q "^Версия: $ver\$" FUNCTIONAL.md || bad "QA-4 FUNCTIONAL.md: строка «Версия:» не равна $ver"
for sec in "HLD" "РАЗВЁРТЫВАНИЯ" "C4 — УРОВЕНЬ 1" "C4 — УРОВЕНЬ 2" "C4 — УРОВЕНЬ 3" "ДЕТАЛЬНОЕ ОПИСАНИЕ"; do
  grep -q "$sec" FUNCTIONAL.md || bad "QA-4 FUNCTIONAL.md: нет раздела «$sec»"
done
if grep -qE "^## $ver — [0-9]{4}-[0-9]{2}-[0-9]{2}\$" CHANGELOG.md 2>/dev/null; then
  ok "QA-4 CHANGELOG.md содержит запись $ver"
else
  bad "QA-4 CHANGELOG.md: нет записи «## $ver — ГГГГ-ММ-ДД»"
fi
python3 -c "import release_digest as r; assert any(x['version']=='$ver' for x in r.load_releases())" 2>/dev/null \
  || bad "QA-4 release_digest не разбирает запись $ver в CHANGELOG.md"
for doc in GLOBALPING.md QA_QC.md; do
  if [ -f "$doc" ] && grep -qE "monitor\.[0-9]+" "$doc" && ! grep -q "$ver" "$doc"; then
    bad "QA-4 $doc ссылается на другую версию (ожидается $ver)"
  fi
done

# QA-5. Зависимости: всё, что импортируется, перечислено в requirements.txt.
for mod in cryptography aiohttp psycopg2 playwright whois bcrypt requests; do
  pkg=$mod; [ "$mod" = psycopg2 ] && pkg=psycopg2-binary; [ "$mod" = whois ] && pkg=python-whois
  if grep -qE "^(import|from) $mod" ./*.py && ! grep -qiE "^$pkg" requirements.txt; then
    bad "QA-5 $mod импортируется, но нет в requirements.txt"
  fi
done
ok "QA-5 зависимости проверены"

# QA-6. Файлы, нужные в рантайме, попадают в образ.
for f in certs/intermediates.pem favicon.ico; do
  git ls-files --error-unmatch "$f" >/dev/null 2>&1 || bad "QA-6 $f не в git — не попадёт в образ"
done
grep -q "^COPY \. \." Dockerfile || bad "QA-6 Dockerfile не копирует проект целиком"
ok "QA-6 состав образа"

# QA-7. Безопасность: известные уязвимости не должны уйти незамеченными.
if grep -nE "== *\"authenticated_(sibur|admin)\"" app.py >/dev/null; then
  note "QA-7 SEC-1: значения cookie сессии статичны (authenticated_sibur/authenticated_admin) — их можно подделать"
fi
if grep -nE "print\(.*(password|passwd|token|secret)" -i ./*.py | grep -v "\*\*\*" >/tmp/qa_sec.log; then
  note "QA-7 возможный вывод секретов в журнал: $(head -2 /tmp/qa_sec.log)"
fi

# QA-8. Рабочее дерево чистое: в релиз уходит ровно то, что проверено.
if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
  note "QA-8 есть незакоммиченные изменения — проверено не то, что уйдёт в main"
else
  ok "QA-8 рабочее дерево чистое"
fi

echo
echo "Итог QA: FAIL=$fail WARN=$warn"
[ "$fail" -eq 0 ]
