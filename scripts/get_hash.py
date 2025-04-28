from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
password_to_hash = input("Введите пароль администратора для хеширования: ")
hashed_password = pwd_context.hash(password_to_hash)
print("\nХеш пароля (сохраните это значение в .env как ADMIN_PASSWORD_HASH):")
print(hashed_password)