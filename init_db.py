from db import init_database, create_default_admin

init_database()
create_default_admin()

print("Database initialization complete.")