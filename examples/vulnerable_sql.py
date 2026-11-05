"""Intentionally vulnerable SQL construction used in the dashboard demo."""

def search(cursor, search_term):
    search_term = input("Search: ")
    return cursor.execute("SELECT * FROM products WHERE name LIKE '%" + search_term + "%'")
