from iam_guardian.core.secrets import (
    get_database_url,
    get_groq_key,
    get_secret_key,
)

GROQ_API_KEY = get_groq_key()
DATABASE_URL = get_database_url()
SECRET_KEY = get_secret_key()
