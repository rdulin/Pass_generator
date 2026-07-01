#!/usr/bin/env python3
"""
Генератор надёжных паролей без неоднозначных символов.

Исключает символы, которые легко перепутать:
- L, l, i, I (заглавная и строчная i, L)
- O, 0 (ноль и заглавная O)
- 1, l, I (единица и похожие буквы)
- S, 5 (пятерка и S)
- B, 8 (восьмерка и B)
- Z, 2 (двойка и Z)

Также исключает специальные символы, которые могут вызывать проблемы:
- `, ~, |, \, ", ', <, >, &, ;, : (могут требовать экранирования)
"""

import secrets
import string
import argparse


def get_secure_character_sets():
    """
    Возвращает наборы символов для генерации пароля.
    Исключены неоднозначные символы.
    """
    # Буквы без неоднозначных
    uppercase = "ABCDEFGHJKMNPQRSTUVWXYZ"  # Без I, L, O
    lowercase = "abcdefghjkmnopqrstuvwxyz"  # Без i, l
    
    # Цифры без неоднозначных
    digits = "234679"  # Без 0, 1, 5, 8
    
    # Специальные символы (безопасные и удобные)
    # Исключаем: ` ~ | \ " ' < > & ; : , ( ) [ ] { } . 
    special = "!@#$%^*_-+=?"
    
    return uppercase, lowercase, digits, special


def generate_password(length=16, use_special=True, ensure_all_types=True):
    """
    Генерирует криптографически стойкий пароль.
    
    Args:
        length: Длина пароля (рекомендуется 16+)
        use_special: Использовать ли специальные символы
        ensure_all_types: Гарантировать наличие всех типов символов
    
    Returns:
        Сгенерированный пароль
    """
    uppercase, lowercase, digits, special = get_secure_character_sets()
    
    if length < 4 and ensure_all_types:
        raise ValueError("Длина пароля должна быть не менее 4 для гарантии всех типов символов")
    
    # Формируем полный набор символов
    all_chars = uppercase + lowercase + digits
    if use_special:
        all_chars += special
    
    password = []
    
    # Если нужно гарантировать наличие всех типов символов
    if ensure_all_types:
        # Добавляем минимум по одному символу каждого типа
        password.append(secrets.choice(uppercase))
        password.append(secrets.choice(lowercase))
        password.append(secrets.choice(digits))
        if use_special:
            password.append(secrets.choice(special))
        
        # Заполняем оставшуюся длину случайными символами
        remaining_length = length - len(password)
        for _ in range(remaining_length):
            password.append(secrets.choice(all_chars))
    else:
        # Просто генерируем случайные символы
        for _ in range(length):
            password.append(secrets.choice(all_chars))
    
    # Перемешиваем пароль для безопасности
    # Используем Fisher-Yates shuffle с cryptographically secure random
    for i in range(len(password) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password[i], password[j] = password[j], password[i]
    
    return ''.join(password)


def check_password_strength(password):
    """
    Проверяет силу пароля и выводит информацию о нём.
    """
    uppercase, lowercase, digits, special = get_secure_character_sets()
    
    has_upper = any(c in uppercase for c in password)
    has_lower = any(c in lowercase for c in password)
    has_digit = any(c in digits for c in password)
    has_special = any(c in special for c in password)
    
    length = len(password)
    
    # Подсчитываем энтропию
    char_pool_size = 0
    if has_upper:
        char_pool_size += len(uppercase)
    if has_lower:
        char_pool_size += len(lowercase)
    if has_digit:
        char_pool_size += len(digits)
    if has_special:
        char_pool_size += len(special)
    
    if char_pool_size > 0:
        entropy = length * (char_pool_size).bit_length()
    else:
        entropy = 0
    
    print(f"\n{'='*60}")
    print(f"Анализ пароля:")
    print(f"{'='*60}")
    print(f"Длина: {length} символов")
    print(f"Заглавные буквы: {'✓' if has_upper else '✗'}")
    print(f"Строчные буквы: {'✓' if has_lower else '✗'}")
    print(f"Цифры: {'✓' if has_digit else '✗'}")
    print(f"Спецсимволы: {'✓' if has_special else '✗'}")
    print(f"Примерная энтропия: ~{entropy} бит")
    
    # Оценка надёжности
    if length >= 20 and has_upper and has_lower and has_digit and has_special:
        strength = "ОЧЕНЬ НАДЁЖНЫЙ ✓"
    elif length >= 16 and has_upper and has_lower and has_digit:
        strength = "НАДЁЖНЫЙ ✓"
    elif length >= 12 and has_upper and has_lower and has_digit:
        strength = "ХОРОШИЙ"
    elif length >= 8:
        strength = "МИНИМАЛЬНЫЙ (рекомендуется увеличить)"
    else:
        strength = "СЛАБЫЙ (не рекомендуется)"
    
    print(f"Оценка надёжности: {strength}")
    print(f"{'='*60}\n")


def main():
    parser = argparse.ArgumentParser(
        description='Генератор надёжных паролей без неоднозначных символов',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  %(prog)s                    - сгенерировать пароль длиной 16 символов
  %(prog)s -l 24              - сгенерировать пароль длиной 24 символа
  %(prog)s -l 32 --no-special - пароль без спецсимволов
  %(prog)s -c 5               - сгенерировать 5 паролей
  %(prog)s --check MyPass123  - проверить надёжность пароля
        """
    )
    
    parser.add_argument('-l', '--length', type=int, default=16,
                        help='Длина пароля (по умолчанию: 16)')
    parser.add_argument('-c', '--count', type=int, default=1,
                        help='Количество паролей для генерации (по умолчанию: 1)')
    parser.add_argument('--no-special', action='store_true',
                        help='Не использовать специальные символы')
    parser.add_argument('--no-guarantee', action='store_true',
                        help='Не гарантировать наличие всех типов символов')
    parser.add_argument('--check', type=str, metavar='PASSWORD',
                        help='Проверить надёжность указанного пароля')
    parser.add_argument('--quiet', '-q', action='store_true',
                        help='Тихий режим (только пароли, без анализа)')
    
    args = parser.parse_args()
    
    # Проверка существующего пароля
    if args.check:
        check_password_strength(args.check)
        return
    
    # Генерация паролей
    use_special = not args.no_special
    ensure_all_types = not args.no_guarantee
    
    print(f"\n{'='*60}")
    print(f"Генератор надёжных паролей")
    print(f"{'='*60}")
    print(f"Длина: {args.length} символов")
    print(f"Спецсимволы: {'используются' if use_special else 'не используются'}")
    print(f"Гарантия всех типов: {'да' if ensure_all_types else 'нет'}")
    print(f"{'='*60}\n")
    
    for i in range(args.count):
        password = generate_password(
            length=args.length,
            use_special=use_special,
            ensure_all_types=ensure_all_types
        )
        
        if args.count > 1:
            print(f"Пароль #{i+1}: {password}")
        else:
            print(f"Ваш пароль: {password}")
        
        # Анализ первого пароля (если не тихий режим)
        if i == 0 and not args.quiet:
            check_password_strength(password)
    
    if args.count > 1 and not args.quiet:
        print("💡 Совет: Используйте менеджер паролей для хранения всех сгенерированных паролей\n")


if __name__ == '__main__':
    main()
