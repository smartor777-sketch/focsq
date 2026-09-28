# Фикс FOCSQ: туннель поднимается, но данные не идут

> Дефект записи TUN: служебный однобайтовый ответ сервера `0xFF` убивал задачу
> записи туннеля, после чего трафик вставал навсегда.
>
> Статус: **исправлено и проверено в рантайме** (6:31 непрерывной работы).
> Оформлено: [issue #2](https://github.com/luminescq/focsq/issues/2) и
> **[PR #3](https://github.com/luminescq/focsq/pull/3)** (открыт, `mergeable`).
> Дифф: 2 файла, `+118 / −7`.
>
> Исходники с фиксом: [smartor777-sketch/focsq](https://github.com/smartor777-sketch/focsq)
> (ветка `main` и `fix/tun-write-dropped`, коммит `12a9564`).
> Локально: `/home/user/src/focsq`.
>
> **Готовый бандл Linux x64 с фиксом:**
> [focsq-linux-x64-v1.0.0-tunfix.tar.gz](https://github.com/smartor777-sketch/focsq/blob/main/releases/focsq-linux-x64-v1.0.0-tunfix.tar.gz)
> (sha256 `d10b530a…`, 56 файлов) — детали в [разделе 11](#11-форк-исходники-и-сборки-для-скачивания).

---

## 1. Симптом

Туннель формально поднимается:

- рукопожатие с сервером проходит, аутентификация успешна;
- интерфейс `csqtt` появляется (`10.70.0.2/24`);
- маршруты ставятся: `0.0.0.0/1` и `128.0.0.0/1` через `10.70.0.1` (half-маршруты, MTU 1300);
- в GUI счётчики активности растут первые секунды.

Но **данные не идут**: сайты не открываются, `bytes_up/down` застывают
(наблюдалось на ~399 КБ down / ~213 КБ up). Приложение выглядит
«подключённым», трафика нет.

Смерть наступает через **5–22 секунды** после первой записи данных
(на трёх старых сессиях — по 14 с от момента `Протокол: TURN`).

---

## 2. Доказательная цепочка

### 2.1. Что записывает процесс (strace)

Захват записи: `trace=write,writev,pwrite64,pwritev2`.

```
70207 06:54:28.490801 write(38, "\377", 1) = -1 EINVAL (Недопустимый аргумент)
```

- fd 38 — TUN-интерфейс;
- payload — ровно **1 байт `0xFF`**, запись полная (не усечённая);
- строка 27365 лога `/home/user/src/focsq-fix/logs/focsq-strace.log`;
- tid 70207, момент — через 22 с после первой data-записи (06:53:54).

Сразу после этой строки трафик встаёт.

### 2.2. Почему `EINVAL` — проблема клиента, а не машины

Изолированное воспроизведение на голом `/dev/net/tun`
(`/home/user/src/focsq-fix/tun_probe.py`, запуск через `focsq-tun`):

| содержимое | результат |
|---|---|
| `len = 0` | `EINVAL` |
| `0x55…` (версия IP не 4 и не 6) | `EINVAL` |
| `0x00…` | `EINVAL` |
| валидный IPv4 | `OK` |
| валидный IPv6 | `OK` |
| валидные фрагменты | `OK` |

Вывод: **`EINVAL` на записи в TUN = «это не валидный IP-пакет»**. Штатное
поведение ядра, ничего необычного на стороне ОС.

### 2.3. Почему `0xFF` сгенерирован сервером, а не подделан

Аутентификация ChaCha20-Poly1305 прошла ⇒ пакет расшифрован ключом, которым
располагает только легитимный ключообладатель. Значит, байт пришёл с сервера,
а не извне и не из-за повреждения.

Альтернативы исключены проверками:

- **Частичных записей нет** — все 775 `write(38,…)` в захвате полные
  (42 пары `<unfinished>`/`resumed` сходятся);
- **усечённого маркера нет** — в бинарнике `wdtt-server` отсутствуют литералы
  вида `\xffCSQTT_*`, то есть `0xFF` — не обрезанный префикс служебной команды.

### 2.4. Источник `0xFF`

Клиентский TURN-keepalive в `backend/turn_core.rs:763-772` шлёт ChannelData с
payload = 1 байт `0xFF`, интервал `KEEPALIVE_INTERVAL = 10s`
(`turn_core.rs:74`). В журнале сервера после фикса отброшено **70 таких
пакетов за 6:31** — то есть дефект воспроизводился бы каждые ~10 секунд.

В серверном журнале литералов `FF-control` = 0 записей (datapath-логирование
выключено: `"datapath_log":false`), поэтому серверную сторону наблюдать
напрямую не удалось.

---

## 3. Корневая причина — два независимых бага

Оба необходимы: первый пропускает мусор до TUN, второй превращает одну
неудачную запись в смерть туннеля.

### 3.1. Баг №1 — `session.rs`, фильтры `reader_loop` не покрывают `0xFF`

`reader_loop` отсекает служебные ответы (`session.rs:1126-1157`):
`is_panel_restart_notice`, `parse_stream_repair`, `parse_stream_alive`,
`shutdown.observe_control_response`, `TUNCONF:`, `is_control_response`.

Но разбор идёт через `strip_prefix`, которому нужен **полный префикс**
(`TUNCONF:`, `READY_OK`, `OK:disconnected`, `STREAM_REPAIR`, `STREAM_ALIVE`).
Одиночный байт `0xFF` ни под один не попадает, проверок IP нет — и пакет
уходит в `dispatcher.return_packet` (`session.rs:600`), а оттуда в запись в TUN.

### 3.2. Баг №2 — `dispatcher.rs:926`, `Failed => return`

```rust
// try_write_tun_packet, ветка записи
Ok(Err(error)) => {
    crate::log_error!("[ОШИБКА] Запись TUN завершена: {error}");
    TunWriteState::Failed
}

// write_tun, обработка состояния
TunWriteState::Closed | TunWriteState::Failed => return,   // ← writer умирает навсегда
```

Задача записи завершается. Дальше `run_tun` (`dispatcher.rs:643-658`) уходит в
`tokio::select!` и ждёт **замену FD** (`replacements.recv()`), которая при живом
интерфейсе никогда не придёт: `None` → `return`. Туннель остаётся поднятым, но
мёртвым — до полного переподключения.

Отсюда характерный набор: маршруты на месте, GUI говорит «подключено», трафика
нет.

### 3.3. Это не форковый дефект

В апстриме `amurcanov/csqtt` та же самая строка. Форк `luminescq/focsq`
добавил только диагностический лог первого data-пакета в `reader_loop`.

---

## 4. Исправление

Правки только в Rust-части (`csqtt-core`), **Flutter-часть не трогалась**:
библиотека подключается через `dlopen("librust_lib_frontend.so")` из
`libapp.so`, поэтому достаточно подменить один файл.

### 4.1. Рубеж №1 — `backend/session.rs`: фильтр не-IP пакетов

После всех служебных проверок, **перед** `deliver_inbound_packet`:

```rust
if !is_ip_packet(packet.as_slice()) {
    dropped_non_ip += 1;
    if dropped_non_ip <= 8 || dropped_non_ip.is_multiple_of(1000) {
        crate::log_error!(
            "[СЕССИЯ] Отброшен не-IP пакет от пира #{}: {} байт, \
             первый байт 0x{:02X}",
            dropped_non_ip,
            packet.len(),
            packet.as_slice().first().copied().unwrap_or_default()
        );
    }
    continue;
}
```

```rust
/// Пакет из канала данных пригоден для записи в TUN-интерфейс.
///
/// Ядро Linux принимает в TUN только валидные пакеты IPv4/IPv6; всё прочее
/// (служебные однобайтовые ответы сервера, усечённые или мусорные датаграммы)
/// запись отвергает с `EINVAL`. Раньше такая запись убивала задачу записи TUN
/// навсегда, поэтому непригодные пакеты отбрасываются ещё в reader_loop.
fn is_ip_packet(packet: &[u8]) -> bool {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) => {
            if packet.len() < 20 {
                return false;
            }
            let header_len = usize::from(packet[0] & 0x0f) * 4;
            (20..=packet.len()).contains(&header_len)
        }
        Some(6) => packet.len() >= 40,
        _ => false,
    }
}
```

Почему именно так:

- проверка зеркалит логику `selective_fec.rs::ipv4_transport/ipv6_transport`
  (IHL ≥ 5 и укладывается в длину пакета, IPv6 — минимум 40 байт);
- **не** проверяет `tot_len` — потому что обрезанный IP в TUN записывается
  успешно (ядро дропает его уже на приёме), а лишняя строгость рискует
  отбрасывать легитимный трафик;
- фильтр стоит **после** служебных разборов: `TUNCONF:` и прочие — не IP, их
  надо обрабатывать, а не отбрасывать;
- лог троттлится (первые 8 + каждое 1000-е), чтобы keepalive-поток не забивал
  журнал.

### 4.2. Рубеж №2 — `backend/dispatcher.rs`: writer больше не умирает

```rust
enum TunWriteState {
    Complete,
    Continue,
    Wait,
    Backoff,
    Yield,
    Closed,
    /// [FOCSQ] Пакет отвергнут ядром (например, не является IP-пакетом) —
    /// он отбрасывается, задача записи TUN продолжает работать.
    Dropped,          // вместо Failed
}
```

```rust
TunWriteState::Yield => tokio::task::yield_now().await,
// [FOCSQ] Неудачная запись одного пакета больше не убивает
// задачу записи: пакет отбрасываем и берём следующий.
TunWriteState::Dropped => {
    pending = None;          // текущий пакет отброшен, цикл берёт следующий
}
TunWriteState::Closed => return,
```

В `try_write_tun_packet` обе неизлечимые ветки возвращают `Dropped`:

```rust
Ok(Ok(0)) => {
    log_dropped_packet(dropped, "запись вернула 0 байт");
    TunWriteState::Dropped
}
...
Ok(Err(error)) => {                       // EINVAL / EMSGSIZE / прочее
    log_dropped_packet(dropped, &error.to_string());
    TunWriteState::Dropped
}
```

`*dropped = 0` сбрасывается на любой успешной записи — счётчик считает именно
непрерывную серию отказов.

Троттлинг лога:

```rust
fn log_dropped_packet(counter: &mut u64, reason: &str) {
    *counter += 1;
    if *counter <= 8 || counter.is_multiple_of(1000) {
        crate::log_error!("[ОШИБКА] Запись TUN: пакет #{counter} отброшен ({reason})");
    }
}
```

**Что сознательно НЕ тронуто:**

- `Closed` (`EIO`/`EBADF`/`ENODEV`) оставлен прежним `return` — это реально
  мёртвый FD, там штатная логика ожидания замены (`run_tun`);
- `is_retryable_tun_error` (`EINTR`/`EAGAIN`/`ENOBUFS`/`ENOMEM`) →
  `Yield`/`Backoff` — без изменений;
- `Ok(Ok(length))` и подсчёт `total_bytes_down` — без изменений.

---

## 5. Триггеры `EINVAL`, воспроизведённые изолированно

| содержимое | длина | результат |
|---|---|---|
| пустой пакет | 0 | `EINVAL` |
| `0xFF` (наш случай) | 1 | `EINVAL` |
| `0x55…` | 60 | `EINVAL` |
| `0x00…` | 60 | `EINVAL` |
| IPv4 `0x45`, IHL=5 | 60 | `OK` |
| IPv4 `0x4f`, IHL=15 | 60 | `OK` |
| IPv6 `0x60` | 40 | `OK` |
| валидный фрагмент | — | `OK` |
| IPv4, заголовок короче 20 байт | 4 | `EINVAL` |

---

## 6. Сборка и развёртывание

### Инструменты (поставлены без `sudo`, в домашнем каталоге)

| инструмент | версия | куда |
|---|---|---|
| Rust / cargo | 1.98.1 | `~/.cargo`, `~/.rustup` |
| CMake | 3.31.6 | `~/.local/opt/cmake` (нужен `aws-lc-sys`) |

Требование `rust-version = "1.97.1"` (edition 2024) выполнено.

### Сборка

```bash
. "$HOME/.cargo/env"
export PATH="/home/user/.local/opt/cmake/bin:$PATH"

cd /home/user/src/focsq/backend
cargo check --release
cargo test --release ip_filter

cd /home/user/src/focsq/frontend/rust
cargo build --release
```

Кодоген `flutter_rust_bridge` не нужен — `src/frb_generated.rs` уже в репо.

### Развёртывание

```bash
/home/user/src/focsq-fix/deploy-fix.sh
# или вручную:
cp -f /home/user/lib/librust_lib_frontend.so{,.orig}   # бэкап (однократно)
cp -f target/release/librust_lib_frontend.so /home/user/lib/librust_lib_frontend.so
```

Замена делается при **выключенном** FOCSQ (иначе — запись в текстовый сегмент
живого процесса).

### Откат

```bash
cp -f /home/user/src/focsq-fix/librust_lib_frontend.so.orig /home/user/lib/librust_lib_frontend.so
```

md5 оригинала: `ef45442e02bc9bf733edc23ac1bb0bf1`.

---

## 7. Проверка

### Статические

- `cargo check --release` — чисто; 3 предупреждения (`dead_code`:
  `CLIENT_WORKER_PACKET_CHUNK`, `begin_with_count`, `suspend`) — **посторонние**,
  присутствовали и до правок;
- `cargo test --release ip_filter` — **3 passed**:
  `ip_filter_accepts_valid_packets`,
  `ip_filter_rejects_server_control_bytes`,
  `ip_filter_rejects_truncated_headers`;
- в собранном `.so` строка фикса присутствует, а старая
  `Запись TUN завершена` — **отсутствует** (в оригинале была).

### Рантайм: до / после

| показатель | до | после |
|---|---|---|
| `Запись TUN завершена` | на первой секунде | **0** |
| `Интерфейс опущен` | да | **0** |
| `bytes_down` | застыли на 399 949 | 3 648 723 и растут |
| `bytes_up` | застыли на 213 372 | 4 552 617 и растут |
| сайты | не открываются | `example.com → 200, 0.29 с` |
| внешний IP | — | `203.0.113.10` (через туннель) |
| время жизни | 5–22 с | 6:31+ без происшествий |

Журнал после фикса:

```
[СЕССИЯ] Первый data-пакет от пира: 60 байт
[СЕССИЯ] Отброшен не-IP пакет от пира #1: 1 байт, первый байт 0xFF
```

70 отброшенных `0xFF` за 6:31 — доказательство, что сервер шлёт их каждые
~10 с и до фикса каждый такой пакет был потенциальной смертью туннеля.

### Сторона сервера

```json
{"active":1,"csqtt_sessions":9,"vpn_active":true,
 "online":[{"device_id":"85dd2c12-…","ip":"10.70.0.2","mode":"csqtt"}],
 "up_gb":"0.01","down_gb":"0.04"}
```

`iptables -L INPUT -n -v` на 46000: `11028 5072K ACCEPT` — трафик реально идёт.

---

## 8. Окружение

- FOCSQ `1.0.0+1`, `csqtt-core 2.1.9`, форк от `bfa176f`
- Linux x86_64, Ubuntu 24.04, TUN без `IFF_PI`, адрес `10.70.0.2`, MTU 1300
- сервер `wdtt-server` (`root@vpn.example`), режим CSQTT, UDP 46000,
  `device_id 85dd2c12-…`
- маршрут всегда TURN, пир не исключается, half-маршруты `0.0.0.0/1` + `128.0.0.0/1`

---

## 9. Файлы

Краткая выжимка; полная карта расположения (включая клон апстрима и каталог
`evidence/`) — в разделе [11.3](#113-где-что-лежит-на-машине).

| файл | назначение |
|---|---|
| `/home/user/src/focsq/backend/session.rs` | рубеж №1: `is_ip_packet`, фильтр, 3 теста |
| `/home/user/src/focsq/backend/dispatcher.rs` | рубеж №2: `Dropped` вместо `Failed` |
| `/home/user/lib/librust_lib_frontend.so` | подменяемая библиотека (оригинал — бэкап ниже) |
| `/home/user/src/focsq-fix/librust_lib_frontend.so.orig` | оригинал для отката |
| `/home/user/src/focsq-fix/deploy-fix.sh` | скрипт подмены/отката |
| `/home/user/src/focsq-fix/start-focsq-fix.sh` | лаунчер с фиксом |
| `/home/user/src/focsq-fix/logs/focsq-run-fixed.log` | журнал рантайм-проверки |
| `/home/user/src/focsq-fix/logs/focsq-strace.log` | захват записи; убийца — строка 27365 |
| `/home/user/src/focsq-fix/tun_probe.py` | изолированное воспроизведение `EINVAL` |
| `/home/user/src/focsq-fix/issue-focsq.md` | текст issue |

---

## 10. Связанные записи

- Ишью автору сборки: [luminescq/focsq#2](https://github.com/luminescq/focsq/issues/2)
- **PR с фиксом: [luminescq/focsq#3](https://github.com/luminescq/focsq/pull/3)**
  (1 коммит, 2 файла, `+118 / −7`, `mergeable`; ветка `fix/tun-write-dropped`)
- Симптом у пользователей панели: [ildarmaga/wdtt#48](https://github.com/ildarmaga/wdtt/issues/48)
  (15 комментариев, `Запись Tun завершена: Invalid argument`, ответ автора
  от 2026-09-22 «пока не исправлял это»)
- Первопричина в апстриме: [amurcanov/csqtt](https://github.com/amurcanov/csqtt) —
  та же строка `dispatcher.rs:924`

### Что ещё можно сделать (не сделано)

1. **Патч в `amurcanov/csqtt`** — дефект там тоже есть; апстрим обычно закрывает
   issue только изменением кода, поэтому нужен именно PR, а не описание.
   На `bfa176f` патч ложится чисто (`git apply --check`) — там та же база.
2. **Комментарий в `ildarmaga/wdtt#48`** — отсылка на решение, чтобы 15 человек,
   ищущих причину, нашли фикс.
3. **Разбор серверной стороны** — подтвердить, что `0xFF` — это штатный
   keepalive/ack, а не дефект wrap-логики. Для этого нужен захват `read*`
   (трассировались только `write*`) и серверные исходники.

---

## 11. Форк, исходники и сборки для скачивания

### 11.1. Репозиторий

**https://github.com/smartor777-sketch/focsq** — публичный **форк** `luminescq/focsq`,
ветка `main`. Связь с апстримом восстановлена, PR отправлен:
**[luminescq/focsq#3](https://github.com/luminescq/focsq/pull/3)** (`mergeable`).

История с переименованиями: форк создавался через `gh repo fork`, но после
перевода в приватный и обратно в публичный GitHub **разорвал связь с
оригиналом** (`isFork:false`, `parent:null`) — PR из такого репозитория
невозможен, API отдаёт `Validation Failed` (head обязан быть форком base).
Чтобы вернуть PR, пришлось переименовать наше репо в **`focsq-local`**
(осталось как архив с теми же коммитами) и форкнуть `luminescq/focsq` заново —
имя `focsq` освободилось, связь восстановилась.

Коммиты в форке (на `main`):

```
e811136 (main)  README: ссылка на документацию и бандл с фиксом
59cc4fd         Add Documentation: разбор дефекта записи TUN
4c69ab8         Add Linux bundle v1.0.0-tunfix
12a9564 (fix/tun-write-dropped)  Fix TUN write death: drop non-IP packets
bfa176f (tag: v1.0.0)  1.0.0            ← апстрим
```

В **PR #3** идёт только ветка `fix/tun-write-dropped` — 1 коммит, 2 файла,
`+118 / −7`. Ветку `main` в PR не включали намеренно: туда попал бы
17-мегабайтный бинарь архива.

Все ссылки на `smartor777-sketch/focsq/…` после переименований продолжают
работать — новый форк занял то же имя и содержит те же пути.

### 11.2. Где лежат исходники `librust_lib_frontend.so`

Корень: **`/home/user/src/focsq/`**. Сборка — из двух crates:

```
/home/user/src/focsq/
├── frontend/rust/          ← crate rust_lib_frontend (контейнер, собирается в .so)
│   ├── Cargo.toml          crate-type = ["cdylib", "staticlib"]
│   ├── src/
│   │   ├── lib.rs
│   │   └── frb_generated.rs   ← мост flutter_rust_bridge (уже в git, кодоген не нужен)
│   └── target/release/librust_lib_frontend.so   ← РЕЗУЛЬТАТ (15 970 720 б)
│
└── backend/                ← crate csqtt-core, path-зависимость
    ├── Cargo.toml          ← здесь name = "csqtt-core"
    ├── session.rs          ← рубеж №1: is_ip_packet(), фильтр, 3 теста
    ├── dispatcher.rs       ← рубеж №2: TunWriteState::Dropped
    ├── auth.rs / protocol.rs / obfs.rs / dns.rs …
    └── vendor/primp/       ← патч-зависимость из репо
```

Связка из `frontend/rust/Cargo.toml`:

```toml
[lib]
crate-type = ["cdylib", "staticlib"]
name = "rust_lib_frontend"

[dependencies]
csqtt-core = { path = "../../backend" }
primp      = { path = "../../backend/vendor/primp" }
```

Где правки (коммит `12a9564`):

| файл | что |
|---|---|
| `backend/session.rs` | `is_ip_packet()` + фильтр в `reader_loop` + 3 юнит-теста |
| `backend/dispatcher.rs` | `TunWriteState::Failed` → `Dropped`, `log_dropped_packet()` |

`du` по `frontend/rust` и `backend` показывает сотни мегабайт — это вместе с
каталогом `target/`, сами исходники весят пару мегабайт.

### 11.3. Где что лежит на машине

| путь | назначение |
|---|---|
| `/home/user/src/focsq/` | git-репозиторий, исходники, сборка `.so` |
| `/home/user/src/focsq-fix/` | скрипты, бэкап, логи, доказательная база |
| `/home/user/src/focsq-fix/librust_lib_frontend.so.orig` | оригинал `ef45442e…` для отката |
| `/home/user/src/focsq-fix/deploy-fix.sh` | подмена/откат `.so` |
| `/home/user/src/focsq-fix/start-focsq-fix.sh` | лаунчер с фиксом |
| `/home/user/src/focsq-fix/logs/focsq-strace.log` | захват записи, убийца — строка 27365 |
| `/home/user/src/focsq-fix/tun_probe.py` | изолированное воспроизведение `EINVAL` |
| `/home/user/src/focsq-fix/evidence/` | копии файлов апстрима/форков для сравнения |
| `/home/user/src/csqtt-upstream/` | клон `amurcanov/csqtt` (`ace2122`) |
| `/home/user/lib/librust_lib_frontend.so` | развёрнутая сборка `68adbef2…` |
| `/home/user/focsq.sh` | штатный лаунчер автора (отличается от репозиторного только BOM) |

### 11.4. Сборки для скачивания

**Страница файла в репозитории:**
https://github.com/smartor777-sketch/focsq/blob/main/releases/focsq-linux-x64-v1.0.0-tunfix.tar.gz

**Прямая ссылка на скачивание** (без страницы GitHub):

```
https://raw.githubusercontent.com/smartor777-sketch/focsq/main/releases/focsq-linux-x64-v1.0.0-tunfix.tar.gz
```

| | |
|---|---|
| имя файла | `focsq-linux-x64-v1.0.0-tunfix.tar.gz` |
| размер | 17 702 518 б |
| md5 | `87aa13f1607d772dac352537f075651f` |
| sha256 | `d10b530a9909cbc35b7489253a15c4b332b9b21dc708a0b86de609e184c63701` |
| файлов | 56 (55 оригинала + `README.md`) |
| коммит | `4c69ab8` |

Что внутри: ровно оригинальный бандл автора `focsq-linux-x64.tar.gz`
(состав, права и владельцы совпадают) плюс `README.md` с инструкцией и
описанием фикса. Единственное отличие от оригинала — `lib/librust_lib_frontend.so`:

| | md5 | размер |
|---|---|---|
| оригинал автора | `ef45442e02bc9bf733edc23ac1bb0bf1` | 15 917 488 |
| **с фиксом** | `68adbef2952df1e028539e004010ef7a` | 15 970 720 |

Это та же сборка, что проверена в рантайме (md5 собранного `.so` совпадает
с развёрнутым в `/home/user/lib/`).

Установка:

```bash
mkdir -p focsq && cd focsq
tar xzf ../focsq-linux-x64-v1.0.0-tunfix.tar.gz
./focsq.sh
```

Архив кладётся в текущий каталог без вложенной папки. При первом запуске
`focsq.sh` проверит библиотеки, выдаст `cap_net_admin` через `pkexec` и
добавит пункт меню (`--install` / `--uninstall` — только меню).

Проверено перед публикацией: скачивание архива обратно с GitHub и сверка
sha256 (совпал побайтно), распаковка в чистый каталог (3 исполняемых файла
сохранили `755`), `bash -n` по лаунчеру, `ldd` без `not found`.
