
import sqlite3

connection = sqlite3.connect("minisiem.db")
cursor = connection.cursor()

query = "SELECT name FROM sqlite_master WHERE type = ?"
cursor.execute(query, ("table",))

tables = cursor.fetchall()

print("Tables found in database:")

for table in tables:
    print(table[0])

connection.close()
