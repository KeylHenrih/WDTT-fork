//! Simple pseudorandom nickname generator for wdtt client.
//!
//! Unlike `generate_name`, which produces human‑readable Russian names, a nickname
//! is a short alphanumeric identifier often used for display in UI elements.
//! The implementation mirrors the style of the original Go generator used in the
//! upstream `proxy-turn-vk-android` project (random adjective + noun, optional
//! number).

use rand::Rng;

const ADJECTIVES: [&str; 20] = [
    "Быстрый", "Смелый", "Тихий", "Тёмный", "Яркий", "Лёгкий", "Головастый", "Бешеный",
    "Медленный", "Тёплый", "Хитрый", "Ледяной", "Мрачный", "Огненный", "Пушистый",
    "Светлый", "Складной", "Смутный", "Трудный", "Умный",
];

const NOUNS: [&str; 20] = [
    "Волк", "Лиса", "Медведь", "Кот", "Тигр", "Пантера", "Сокол", "Ястреб",
    "Краб", "Дракон", "Заяц", "Лось", "Орел", "Собака", "Ворон", "Змей",
    "Кролик", "Лев", "Ёж", "Пёс",
];

/// Generate a pseudorandom nickname.
///
/// Format: `<adjective><noun>` optionally followed by a three‑digit number.
/// The number is added with 30 % probability, mirroring the `FIRST_NAME_ONLY`
/// probability used for real names.
pub fn generate_nickname() -> String {
    let mut rng = rand::rng();
    let adj = ADJECTIVES[rng.random_range(0..ADJECTIVES.len())];
    let noun = NOUNS[rng.random_range(0..NOUNS.len())];
    let mut nick = format!("{}{}", adj, noun);
    if rng.random_bool(0.3) {
        // three‑digit number, zero‑padded.
        let num = rng.random_range(0..1000);
        nick = format!("{}{:03}", nick, num);
    }
    nick
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nickname_is_nonempty_and_alphanumeric() {
        let is_cyrillic = |c: char| {
            (c == 'ё')
                || (c == 'Ё')
                || ('\u{0410}'..='\u{042F}').contains(&c)
                || ('\u{0430}'..='\u{044F}').contains(&c)
        };
        for _ in 0..200 {
            let n = generate_nickname();
            assert!(!n.is_empty());
            assert!(
                n.chars().all(|c| c.is_ascii_digit() || is_cyrillic(c)),
                "nickname contains unexpected chars: {n}"
            );
        }
    }
}
