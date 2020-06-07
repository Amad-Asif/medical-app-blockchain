"""
Basic database utils
"""

import sqlite3
from sqlite3 import Error

def get_db_conn(db_file="app.db"):
    conn = None
    try:
        conn = sqlite3.connect(db_file)
    except Error as e:
        print(e)
    return conn

def get_private_key(conn,user_id):
    cur = conn.cursor()
    cur.execute("select public_key from user_keys where user_id = '{}'".format(user_id))
    row = cur.fetchone()
    return row

def get_all_users(conn):
    cur = conn.cursor()
    cur.execute("select * from user_keys")
    rows = cur.fetchall()
    return rows

def get_audit_trail(conn):
    cur = conn.cursor()
    cur.execute("select * from transaction_logs order by event_time desc")
    rows = cur.fetchall()
    return rows