=== ПОЛНОЕ ОПИСАНИЕ ФУНКЦИОНАЛА ===

1. АРХИТЕКТУРА
   - FastAPI + PostgreSQL (партиционированная) + Playwright + aiohttp + Chart.js + BCrypt
   - 4 фоновых потока: check_worker (60с), ssl_whois_worker (4ч), daily_report_worker (09:00), rotation_worker (03:00)
   - 15 API endpoints

2. БАЗА ДАННЫХ
   - logs: партиционированная по timestamp (авто-партиции на 3 мес вперед)
   - checks_agg: 5-мин агрегаты (uptime, avg/min/max response)
   - incidents: история падений с resolved статусом
   - monitored_sites: управляемый список с группами (key/stdo/external/self) + порог алерта
   - health: heartbeat воркера
   - latest_status: materialized view, авто-refresh CONCURRENTLY

3. DASHBOARD (/) — 4 вкладки
   - Список: группировка (Ключевые / СТДО / Внешние), sibur.ru всегда первый, KPI под каждой группой
   - Аналитика: Chart.js графики (14 дней), lazy load, кнопка "Показать все внешние"
   - Инциденты: последние 100 за 30д, первые 20 видны + кнопка, колонка Статус (Active/Resolved)
   - Календарь: SSL + домен, сортировка по дням, прокрутка если широкая таблица

4. KPI БЛОК
   - Доступно: online / total (danger если offline)
   - Uptime: 24ч / 30д (взвешенное среднее из checks_agg)
   - Ответ: 24ч / 30д
   - Инциденты: active + offline (danger если active>0, подпись "(N active)")
   - SSL <=20д: danger если есть
   - ⚠️ Обратите внимание: Offline + SSL <=20 + Задержка >20с + Active инциденты

5. УПРАВЛЕНИЕ (/admin/page) — 3 вкладки
   - Сайты: CRUD (добавить/изменить/вкл/выкл/удалить), группы key/stdo/external, порог мин
   - Self Monitoring: async загрузка /api/self-monitoring (таблица + график + инциденты)
   - Описание: документация функционала (FUNCTIONAL.md через /api/functional)
   - Self-monitoring сайты защищены от изменения/удаления

6. TELEGRAM АЛЕРТЫ
   - Порог по умолчанию: 5 мин (настраивается в Управление → Порог мин для каждого сайта)
   - 🚨 DOWN: fail_count >= threshold + скриншот (3 сек после domcontentloaded)
   - ✅ UP: восстановление + скриншот + длительность (только если был DOWN алерт)
   - 🐢 Задержка: response_time > 20с
   - ⚡ Скорость восстановлена: response_time < 10с после задержки
   - 🔔 SSL отчет: SSL <= 20 дней (09:00 МСК)
   - 🧪 Тест скриншот: по кнопке (rate limit 30 сек/сайт)
   - Retry 3x, exponential backoff, логирование каждого вызова

7. SELF-MONITORING (sib-monitor-ankori.amvera.io)
   - Изолирован: не в KPI "Доступно", не в общей таблице dashboard, не в группах
   - Проверка: любой HTTP-ответ = Online (200), только timeout = Offline (0)
   - Алерты: порог 10 мин, помечены [SELF-MONITORING] в Telegram
   - Cleanup при старте: удаляются старые logs/checks_agg/incidents для SM
   - Fallback Online: если нет в БД — показывает status=200
   - Вкладка только в Управлении (не на главном dashboard)

8. ИНЦИДЕНТЫ + RESOLVED
   - Content match для Ключевых сайтов: при status=200 проверяется наличие текста 'sibur/сибур/СИБУР'
   - Content mismatch: status=701, отображается как 'Content Mismatch', алерт '🚨 DOWN: site (Код: 701)'
   - Инцидент регистрируется только если недоступность >= порога (по умолчанию 5 мин)
   - start_time инцидента = время первого фейла (хранится в first_fail_time)
   - Короткие падения (< порога): в логи пишутся, в incidents — нет, алерта нет
   - resolved: FALSE при создании, TRUE при закрытии
   - UP-алерт отправляется только если был DOWN-алерт
   - Таблица t3: колонка "Статус" (🔴 Active / ✅ Resolved), длительность пересчитывается динамически
   - Active инциденты показываются в блоке "⚠️ Обратите внимание"
   - При старте: закрываются "висящие" unresolved инциденты для сайтов, которые сейчас Online

9. CONTENT MATCH
   - Проверяется для Ключевых сайтов при status=200
   - Паттерн: (?i)(sibur|сибур|СИБУР) — case-insensitive
   - Чтение тела ответа: max 3 сек
   - Не найден или таймаут чтения → status=701 (Content Mismatch)
   - В таблице отображается красным: "Content Mismatch"
   - Алерт: "🚨 DOWN: site (Код: 701)"

10. ОПТИМИЗАЦИИ
    - Batch-вставка: накопление до 50 записей
    - Dashboard кэш: 30 сек, сборка <10 мс
    - Lazy charts: графики подгружаются async после first paint
    - string.Template для JS: устранён конфликт { } между Python f-string и JS
    - Playwright скриншоты: thread-safe, rate limit 30 сек, 3 сек после domcontentloaded
    - Горизонтальная прокрутка таблиц (overflow-x: auto)
    - Столбец "Сайт" nowrap + min-width, столбец "Начало" 11ch

11. АУТЕНТИФИКАЦИЯ
    - Dashboard: Basic Auth + BCrypt + cookie session_auth (30 дней)
    - Admin: отдельный пароль + cookie admin_session (1 день)

=== ИСПРАВЛЕННЫЕ ОШИБКИ ===
1. JS SyntaxError: string.Template вместо f-string в JS
2. alert_threshold=None: защита на 3 уровнях (load_active_sites + _process_site_result + check_worker)
3. ssl_whois_worker не запускался: восстановлен в startup_event
4. Self-monitoring 401→Offline: любой HTTP=Online
5. Висящие unresolved инциденты: закрываются при старте
6. _backfill_incidents: исключает self-monitoring
7. Self-monitoring инициализация: last_status/fail_count/latency_map/first_fail_time
8. Алерт через 1 мин: last_status обновлялся при fail_count==1 (починено)
9. Длительность инцидентов: start_time = время первого фейла (не достижения порога)
10. Календарь пустой: исправлена HTML-структура (закрывающие div)
11. Self-monitoring алерты: добавлены с порогом 10 мин
12. Content match: добавлена проверка текста для Ключевых сайтов
