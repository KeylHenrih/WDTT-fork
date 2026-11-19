//! Pseudorandom display-name generator for anonymous VK Calls sessions.
//!
//! Ported from the original WDTT `core/namegen.go` so an anonymous participant
//! shows up in the call as an ordinary person rather than as `User<number>`.
//! A numeric name is a strong signal to the platform that the participant was
//! not created by a real client, so the real name lists are reproduced here
//! verbatim.

use rand::Rng;

const MALE_FIRST_NAMES: [&str; 39] = [
    "Александр",
    "Алексей",
    "Андрей",
    "Антон",
    "Арсений",
    "Артур",
    "Артём",
    "Богдан",
    "Валерий",
    "Василий",
    "Виктор",
    "Владислав",
    "Глеб",
    "Григорий",
    "Даниил",
    "Денис",
    "Дмитрий",
    "Евгений",
    "Егор",
    "Иван",
    "Игорь",
    "Илья",
    "Кирилл",
    "Леонид",
    "Максим",
    "Марк",
    "Матвей",
    "Михаил",
    "Никита",
    "Николай",
    "Олег",
    "Павел",
    "Пётр",
    "Роман",
    "Руслан",
    "Сергей",
    "Станислав",
    "Тимофей",
    "Фёдор",
];

const FEMALE_FIRST_NAMES: [&str; 31] = [
    "Алина",
    "Алёна",
    "Анастасия",
    "Ангелина",
    "Анна",
    "Вера",
    "Вероника",
    "Виктория",
    "Дарья",
    "Ева",
    "Екатерина",
    "Елена",
    "Елизавета",
    "Ирина",
    "Кира",
    "Кристина",
    "Ксения",
    "Любовь",
    "Маргарита",
    "Марина",
    "Мария",
    "Милана",
    "Надежда",
    "Наталья",
    "Ольга",
    "Полина",
    "Светлана",
    "София",
    "Татьяна",
    "Юлия",
    "Яна",
];

const LAST_NAMES: [&str; 59] = [
    "Алексеев",
    "Андреев",
    "Антонов",
    "Баранов",
    "Белов",
    "Белый",
    "Бельский",
    "Беляев",
    "Борисов",
    "Васильев",
    "Великий",
    "Волков",
    "Воробьёв",
    "Григорьев",
    "Давыдов",
    "Егоров",
    "Жуков",
    "Зайцев",
    "Захаров",
    "Иванов",
    "Калинин",
    "Ковалёв",
    "Козлов",
    "Комаров",
    "Крамской",
    "Кузнецов",
    "Кузьмин",
    "Лебедев",
    "Макаров",
    "Медведев",
    "Михайлов",
    "Морозов",
    "Никитин",
    "Николаев",
    "Новиков",
    "Орлов",
    "Островский",
    "Павлов",
    "Петров",
    "Покровский",
    "Попов",
    "Раевский",
    "Романов",
    "Семёнов",
    "Сергеев",
    "Смирнов",
    "Соколов",
    "Соловьёв",
    "Степанов",
    "Тарасов",
    "Титов",
    "Толстой",
    "Трубецкой",
    "Филиппов",
    "Фролов",
    "Фёдоров",
    "Чайковский",
    "Черный",
    "Яковлев",
];

/// Chance that the generated name is a first name alone, without a surname.
const FIRST_NAME_ONLY_CHANCE: f64 = 0.3;

/// Converts a masculine surname to its feminine form.
///
/// Follows the original rules: `-ий`/`-ый`/`-ой` become `-ая`, and the
/// possessive endings `-ов`/`-ев`/`-ин`/`-ын`/`-ёв` take a trailing `-а`.
/// Anything else is returned unchanged.
fn convert_to_female_surname(surname: &str) -> String {
    for ending in ["ий", "ый", "ой"] {
        if let Some(stem) = surname.strip_suffix(ending) {
            return format!("{stem}ая");
        }
    }
    for ending in ["ов", "ев", "ин", "ын", "ёв"] {
        if surname.ends_with(ending) {
            return format!("{surname}а");
        }
    }
    surname.to_owned()
}

/// Generates a pseudorandom Russian display name.
///
/// The gender is picked at random, then a matching first name. With
/// [`FIRST_NAME_ONLY_CHANCE`] probability only the first name is returned;
/// otherwise a surname is appended and inflected to the chosen gender.
pub fn generate_name() -> String {
    let mut rng = rand::rng();
    let is_female = rng.random_range(0..2) == 0;

    let first = if is_female {
        FEMALE_FIRST_NAMES[rng.random_range(0..FEMALE_FIRST_NAMES.len())]
    } else {
        MALE_FIRST_NAMES[rng.random_range(0..MALE_FIRST_NAMES.len())]
    };

    if rng.random_bool(FIRST_NAME_ONLY_CHANCE) {
        return first.to_owned();
    }

    let last = LAST_NAMES[rng.random_range(0..LAST_NAMES.len())];
    if is_female {
        format!("{first} {}", convert_to_female_surname(last))
    } else {
        format!("{first} {last}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn female_surnames_follow_the_original_rules() {
        assert_eq!(convert_to_female_surname("Бельский"), "Бельская");
        assert_eq!(convert_to_female_surname("Белый"), "Белая");
        assert_eq!(convert_to_female_surname("Толстой"), "Толстая");
        assert_eq!(convert_to_female_surname("Иванов"), "Иванова");
        assert_eq!(convert_to_female_surname("Алексеев"), "Алексеева");
        assert_eq!(convert_to_female_surname("Никитин"), "Никитина");
        assert_eq!(convert_to_female_surname("Соловьёв"), "Соловьёва");
        assert_eq!(convert_to_female_surname("Черный"), "Черная");
        // No matching ending: returned as-is.
        assert_eq!(convert_to_female_surname("Гоголь"), "Гоголь");
    }

    #[test]
    fn generated_names_are_never_numeric() {
        for _ in 0..200 {
            let name = generate_name();
            assert!(!name.is_empty());
            assert!(
                !name.chars().any(|c| c.is_ascii_digit()),
                "name must not contain digits: {name}"
            );
        }
    }

    #[test]
    fn generated_names_use_one_or_two_words() {
        for _ in 0..200 {
            let name = generate_name();
            let words = name.split(' ').count();
            assert!((1..=2).contains(&words), "unexpected word count in {name}");
        }
    }

    #[test]
    fn both_genders_eventually_occur() {
        let mut male = 0;
        let mut female = 0;
        for _ in 0..200 {
            let name = generate_name();
            if LAST_NAMES
                .iter()
                .any(|last| name.ends_with(&convert_to_female_surname(last)) && name.contains(' '))
                || FEMALE_FIRST_NAMES.iter().any(|first| name.starts_with(first))
            {
                female += 1;
            } else {
                male += 1;
            }
        }
        assert!(male > 0, "male names should appear");
        assert!(female > 0, "female names should appear");
    }
}
