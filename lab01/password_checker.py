# ЛР1. Перевірка пароля на зв'язок з персональними даними

# Персональні дані (варіанти написання імені та прізвища латиницею)
NAME_WORDS = ["oleksandra", "aleksandra", "alexandra", "sasha",
              "ryazantseva", "riazantseva", "saashaas"]
DAY = "16"
MONTH = "05"
YEAR = "2006"

# Дати, які можуть бути в паролі
DATE_PARTS = [DAY + MONTH, MONTH + DAY, DAY + MONTH + YEAR[2:],
              DAY + MONTH + YEAR, YEAR]

COMMON_WORDS = ["password", "qwerty", "admin", "123456", "letmein", "пароль"]


def check_password(password):
    """Повертає оцінку 1-10 та список порад."""
    advice = []
    pwd = password.lower()

    # Залишаємо тільки літери й цифри: "16_05" -> "1605", "Olek06#" -> "olek06"
    clean = ""
    for c in pwd:
        if c.isalnum():
            clean += c

    # 1. Базова оцінка за довжиною
    if len(password) >= 14:
        score = 9
    elif len(password) >= 10:
        score = 7
    elif len(password) >= 8:
        score = 5
    else:
        score = 3

    # 2. Чи є в паролі ім'я або прізвище
    has_name = False
    for word in NAME_WORDS:
        if word in clean:
            has_name = True
            advice.append("У паролі є ім'я або прізвище: " + word)
            break

    # 3. Чи є в паролі дата народження
    has_date = False
    for part in DATE_PARTS:
        if part in clean:
            has_date = True
            advice.append("У паролі є частина дати народження: " + part)
            break
    # скорочений рік (06) перевіряємо тільки в кінці пароля
    if not has_date and clean.endswith(YEAR[2:]):
        has_date = True
        advice.append("У паролі є скорочений рік народження: " + YEAR[2:])

    # 4. Словникові слова
    for word in COMMON_WORDS:
        if word in pwd:
            score -= 2
            advice.append("Пароль містить типове слово: " + word)
            break

    # 5. Різноманітність символів
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)

    if not (has_upper and has_lower):
        score -= 1
        advice.append("Використовуйте великі і малі літери.")
    if not has_digit:
        score -= 1
        advice.append("Додайте цифри.")
    if not has_special:
        score -= 1
        advice.append("Додайте спеціальні символи (!, @, #, $).")
    if len(password) < 12:
        advice.append("Рекомендована довжина пароля - від 12 символів.")

    # 6. Особисті дані сильно знижують оцінку
    if has_name:
        score -= 3
    if has_date:
        score -= 3
    if has_name or has_date:
        advice.append("Уникайте особистих даних у паролях.")

    # Оцінка завжди від 1 до 10
    score = max(1, min(10, score))

    if not advice:
        advice.append("Чудовий пароль!")
    return score, advice


def show(password):
    score, advice = check_password(password)
    print("Пароль:", password)
    print("Оцінка:", score, "/ 10")
    for line in advice:
        print("  -", line)
    print("-" * 50)


# Тести
if __name__ == "__main__":
    print("ТЕСТОВІ ПАРОЛІ\n")
    tests = ["sasha16052006", "Oleksandra!2006", "Ryazantseva#0516",
             "160506Sasha", "Sasha.Ryazantseva-06"]
    for t in tests:
        show(t)

    print("\nПЕРЕВІРКА ВЛАСНОГО ПАРОЛЯ")
    while True:
        user_pwd = input("Введіть пароль (Enter - вийти): ")
        if user_pwd == "":
            break
        show(user_pwd)
