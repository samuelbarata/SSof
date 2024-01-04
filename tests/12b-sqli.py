import sqlite3

database_file = 'database.db'
connection = sqlite3.connect(database_file)
cursor = connection.cursor()
request = connection()

u = request.get('Enter username: ')
p = request.get('Enter password: ')

q = f"SELECT * FROM users WHERE user='{u}' AND password='{p}'"

cursor.execute(q)

# real sql injection scenario
