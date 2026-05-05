=== ПОЛНОЕ ОПИСАНИЕ ФУНКЦИОНАЛА ===

1. АРХИТЕКТУРА
   - FastAPI + PostgreSQL (партиционированная) + Playwright + aiohttp + Chart.js + BCrypt
   - 4 фоновых потока: check_worker (60с), ssl_whois_worker (4ч), daily_report_worker (09:00), rotation_worker (03:00)
   - 14 API endpoints

2. БАЗА ДАННЫХ
   - logs: партиционированная по timestamp (авто-партиции на 3 мес вперед)
   - checks_agg: 5-мин агрегаты (uptime, avg/min/max response)
   - incidents: история падений с resolved статусом
   - monitored_sites: управляемый список с группами (key/stdo/external/self)
   - health: heartbeat воркера
   - latest_status: materialized view, авто-refresh CONCURRENTLY

3. DASHBOARD (/) — 4 вкладки
   - Список: группировка (Ключевые / СТДО / Внешние), KPI под каждой группой
   - Аналитика: Chart.js графики, lazy load
   - Инциденты: последние 100 за 30д, первые 20 видны, остальные по кнопке
   - Календарь: SSL + домен, сортировка по дням

4. KPI БЛОК
   - Доступно: online / total (danger если offline)
   - Uptime: 24ч / 30д (взвешенное среднее из checks_agg)
   - Ответ: 24ч / 30д
   - Инциденты: active + offline (danger если active>0)
   - SSL <=20д: danger если есть
   - ⚠️ Обратите внимание: Offline + SSL <=20 + Задержка >20с + Active инциденты

5. УПРАВЛЕНИЕ (/admin/page) — 3 вкладки
   - Сайты: CRUD (добавить/изменить/вкл/выкл/удалить), группы key/stdo/external
   - Self Monitoring: async загрузка /api/self-monitoring (таблица+график+инциденты)
   - Описание: документация функционала (этот файл)

6. TELEGRAM АЛЕРТЫ (только если сайт недоступен >= порога)
   - Порог по умолчанию: 5 мин (задаётся в Управление → Порог мин)
   - Self Monitoring порог: 10 мин (неотключаемый, без алертов)
   - 🚨 DOWN: fail_count >= threshold + скриншот
   - ✅ UP: восстановление + скриншот + длительность
   - 🐢 Задержка: response_time > 20с
   - ⚡ Скорость восстановлена: response_time < 10с после задержки
   - 🔔 SSL отчет: SSL <= 20 дней (09:00 МСК)
   - 🧪 Тест скриншот: по кнопке (rate limit 30 сек/сайт)
   - Retry 3x, exponential backoff, логирование каждого вызова

7. SELF-MONITORING (sib-monitor-ankori.amvera.io)
   - Изолирован: не в KPI, не в общей таблице, не в группах, не в TG алертах
   - Проверка: любой HTTP-ответ = Online, только timeout = Offline
   - Cleanup при старте: удаляются все старые logs/checks_agg/incidents для SM
   - Fallback Online: если нет в БД — показывает status=200
   - Вкладка только в Управлении (не на главном dashboard)

8. ИНЦИДЕНТЫ + RESOLVED
   - resolved: FALSE при создании, TRUE при закрытии
   - last_status обновляется только при отправке DOWN-алерта (fail >= threshold)
   - UP-алерт отправляется только если был DOWN-алерт
   - Короткие падения (< threshold): инцидент в БД, но без алерта в ТГ
   - Startup cleanup: закрывает "висящие" unresolved для сайтов, которые сейчас Online
   - Таблица t3: колонка "Статус" (🔴 Active / ✅ Resolved)
   - Active инциденты показываются в блоке "⚠️ Обратите внимание"

9. ОПТИМИЗАЦИИ
   - Batch-вставка: накопление до 50 записей
   - Dashboard кэш: 30 сек, сборка <10 мс
   - Lazy charts: графики подгружаются async после first paint
   - string.Template для JS: устранён конфликт { } между Python f-string и JS
   - Playwright скриншоты: thread-safe, rate limit 30 сек

10. АУТЕНТИФИКАЦИЯ
    - Dashboard: Basic Auth + BCrypt + cookie session_auth (30 дней)
    - Admin: отдельный пароль + cookie admin_session (1 день)

=== ИСПРАВЛЕННЫЕ ОШИБКИ ===
1. JS SyntaxError: string.Template вместо f-string в JS
2. alert_threshold=None: 3 уровня защиты (load_active_sites + _process_site_result + check_worker)
3. ssl_whois_worker не запускался: восстановлен в startup_event
4. Self-monitoring 401→Offline: любой HTTP=Online, cleanup при старте
5. Висящие unresolved инциденты: last_status обновляется только при алерте
6. _backfill_incidents: исключает self-monitoring
7. Self-monitoring инициализация: last_status/fail_count/latency_map
8. Алерт через 1 мин: last_status не обновлялся при fail_count==1 (починено)
9. Длительность инцидентов: пересчёт через end_time-start_time динамически
