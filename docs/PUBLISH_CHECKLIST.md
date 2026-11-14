# Чек-лист подготовки и публикации репозитория GitHub (`docs/PUBLISH_CHECKLIST.md`)

Данный документ содержит пошаговый перечень настроек безопасности и конфигурации репозитория на GitHub, которые владелец репозитория выполняет перед изменением видимости (переключением в Public).

---

## 1. Настройки безопасности (Security & Analysis)

Перейдите в: **Settings** $\to$ **Code security and analysis**

- [ ] **Secret scanning:** Включить (`Enable`).
  - GitHub автоматически сканирует коммиты на наличие известных форматов токенов и ключей.
- [ ] **Push protection for secret scanning:** Включить (`Enable`).
  - Блокирует `git push`, если в отправляемых коммитах обнаружен токен или секрет.
- [ ] **Dependabot alerts:** Включить (`Enable`).
  - Оповещения об уязвимостях в зависимостях Cargo и GitHub Actions.
- [ ] **Dependabot security updates:** Включить (`Enable`).
  - Автоматическое создание PR с обновлением уязвимых версий библиотек.
- [ ] **Private vulnerability reporting:** Включить (`Enable`).
  - Активирует приватный канал отправки отчётов об уязвимостях через GitHub Security Advisories без создания публичных issue.

---

## 2. Защита основной ветки (Branch Protection Rules)

Перейдите в: **Settings** $\to$ **Branches** $\to$ **Add branch ruleset** (или **Add rule** для `main`):

- [ ] **Branch name pattern:** `main`
- [ ] **Require a pull request before merging:** Включить.
  - Рекомендуется: минимум 1 аппрув (`Required approvals: 1`).
  - Dismiss stale pull request approvals when new commits are pushed: Включить.
- [ ] **Require status checks to pass before merging:** Включить.
  - Require branches to be up to date before merging: Включить.
  - Выбрать обязательные проверки из CI:
    - `Secret Leak Detection (gitleaks)`
    - `Code Formatting and Linter`
    - `License & Advisory Audit`
    - `Unit & Integration Tests (Linux)`
    - `Fuzz Smoke Tests (cargo-fuzz)`
    - `Server Static Musl Build (x86_64)`
    - `Android NDK Build (arm64-v8a)`
- [ ] **Do not allow bypassing the above settings:** Включить (правила действуют и на администраторов).
- [ ] **Restrict deletions and force pushes:**
  - Block force pushes: Включить (`Always block force pushes`).
  - Block branch deletion: Включить.

---

## 3. Права токена GitHub Actions (Workflow Permissions)

Перейдите в: **Settings** $\to$ **Actions** $\to$ **General** $\to$ **Workflow permissions**:

- [ ] Выбрать: **Read repository contents and packages permissions** (минимальные права по умолчанию).
- [ ] Снять галочку: **Allow GitHub Actions to create and approve pull requests** (запрет автоматического слияния от имени бота).
- [ ] В файле `.github/workflows/ci.yml` зафиксирована директива `permissions: read-all` (или `contents: read`).

---

## 4. Закрепление сторонних GitHub Actions по commit SHA

Для защиты от атаки на цепочку поставок (supply chain compromise сторонних Actions) рекомендуется закреплять внешние Actions по полному 40-символьному SHA коммита, а не по плавающему тегу `@v4`:

```yaml
# Пример безопасного закрепления по commit SHA с комментарием версии:
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
- uses: dtolnay/rust-toolchain@master
- uses: Swatinem/rust-cache@82a92a6e8fbeee08c636ad5c42577177d45f76e8 # v2.7.7
- uses: EmbarkStudios/cargo-deny-action@8371184b9963116d0377a49c600f0f465735dd63 # v2.0.12
- uses: gitleaks/gitleaks-action@785d03a110bf02e77b629b35bc5d36e2f49bcf23 # v2.3.9
```

За обновлениями закреплённых версий автоматически следит настроенный [`.github/dependabot.yml`](../.github/dependabot.yml).

---

## 5. Аудит логов предыдущих запусков CI на секреты

Перед изменением видимости приватного репозитория на публичный необходимо убедиться, что логи старых запусков GitHub Actions не содержат конфиденциальных данных:

- [ ] Открыть вкладку **Actions**.
- [ ] Проверить все завершённые запуски (Workflow runs).
- [ ] При создании **нового репозитория** с одним чистым начальным коммитом история старых Actions-запусков **не переносится** (старый репозиторий остаётся приватным архивом либо удаляется).
- [ ] Если используется текущий репозиторий: удалить старые запуски через GitHub API / UI (`Delete workflow run`).

---

## 6. Финальная проверка перед переключением в Public

Перед нажатием кнопки "Change visibility $\to$ Public":
- [ ] Выполнен чистый `git clone` в новую директорию.
- [ ] Запущен `gitleaks detect --source . -v` (0 утечек).
- [ ] Запущен `trufflehog git file://$(pwd)` (0 утечек).
- [ ] Проверен вывод `git log -p` на предмет отсутствия персональных адресов электронной почты и внутренних путей.
- [ ] Проверены файлы `README.md`, `README.en.md`, `LICENSE`, `NOTICE`, `THIRD_PARTY.md`, `SECURITY.md`, `CONTRIBUTING.md`.
