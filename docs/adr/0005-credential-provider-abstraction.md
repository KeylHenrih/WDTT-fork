# ADR 0005: Абстракция провайдера учетных данных TURN (`TurnCredentialProvider`)

## Статус
Принято (Предложено на Этапе 0)

## Контекст
Схема WDTT использует инфраструктуру звонков VK (VK Calls) для получения временных TURN-учётных данных. Поведение и API внешнего сервиса могут измениться в любой момент по решению владельца платформы. Кроме того, пользователям требуется возможность использовать собственные независимые серверы TURN (например, стандартный `coturn`).

В существующих проектах (`vk-turn-proxy`, `PWDTT`) логика авторизации в VK, обработка капчи, генерация браузерных заголовков и поднятие HTTP-серверов жестко впаяна в сетевой код клиента, нарушая принцип разделения ответственности.

## Рассмотренные варианты
1. **Жесткая привязка к VK API:**
   - Не позволяет использовать альтернативные TURN-серверы, усложняет тестирование и адаптацию к блокировкам.
2. **Абстракция через типаж (Trait) `TurnCredentialProvider`:**
   - Полная изоляция специфики VK в отдельном крейте `crates/provider/src/vk`.
   - Поддержка статических учетных данных (`provider/src/static_turn.rs`) и REST API (`provider/src/rest.rs`).
   - Изоляция капчи и веб-взаимодействий через шаблон событий `NeedsUserInteraction`.

## Решение
1. Определить единый асинхронный типаж в `crates/provider`:

```rust
#[async_trait::async_trait]
pub trait TurnCredentialProvider: Send + Sync {
    /// Получить актуальные учетные данные TURN для указанного потока/хеша
    async fn acquire_credentials(
        &self,
        stream_id: u8,
    ) -> Result<TurnCredentials, ProviderError>;

    /// Обновить учетные данные (Refresh / Re-allocation)
    async fn refresh_credentials(
        &self,
        current: &TurnCredentials,
    ) -> Result<TurnCredentials, ProviderError>;

    /// Поток событий провайдера (включая запрос взаимодействия с пользователем)
    fn subscribe_events(&self) -> broadcast::Receiver<ProviderEvent>;
}
```

2. При возникновении капчи или необходимости авторизации провайдер эмитит событие:
   ```rust
   pub enum ProviderEvent {
       NeedsUserInteraction(UserInteractionChallenge),
       CredentialsRefreshed { stream_id: u8, expires_at: u64 },
       RateLimited { retry_after_secs: u32 },
       FatalError(String),
   }
   ```
3. Ядро `crates/core` и сетевой транспорт **не зависят от HTTP, браузеров или WebView**. Обработка `NeedsUserInteraction` делегируется клиентскому интерфейсу (Slint GUI или Android Compose).

## Последствия
- Высокая устойчивость архитектуры: выход из строя или блокировка VK API не ломает сетевое ядро `wdtt-rs`.
- Возможность прямого тестирования ядра против локального `coturn` в Docker без эмуляции запросов к серверам VK.
- Четкие границы ответственности компонентов приложения.
