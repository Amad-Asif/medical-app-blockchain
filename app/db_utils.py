"""
Basic database utils
"""

import sqlite3
from sqlite3 import Error
import time


def get_db_conn(db_file="app.db"):
    conn = None
    try:
        conn = sqlite3.connect(db_file)
    except Error as e:
        print(e)
    return conn


def get_public_key(conn, user_id):
    cur = conn.cursor()
    cur.execute(
        "select public_key from patients where id = '{}'".format(user_id))
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


def insert_audit_trail(conn,id, type, message):
    if not conn:
        conn = get_db_conn()
    # try:
        cur = conn.cursor()
        timeNow = time.ctime()
        sql = "insert into transaction_logs (log,user,event_time, user_type) values('{}','{}','{}','{}')".format(message, id,timeNow, type)
        cur.execute(sql)
        conn.commit()
        return True
    # except Exception as e:
    #     print(e)
    #     return str(e)
        

def insert_doctor(conn, data):
    try:
        cur = conn.cursor()
        sql = 'insert into doctors (name, email, contact, username, password, speciality, experience, public_key) values (?,?,?,?,?,?,?,?)'
        cur.execute(sql, data)
        conn.commit()
        return True
    except Exception as e:
        return str(e)


def insert_patient(conn, data):
    try:
        cur = conn.cursor()
        sql = 'insert into patients (name, email, contact, username, password, public_key) values (?,?,?,?,?, ?)'
        cur.execute(sql, data)
        conn.commit()
        return True
    except Exception as e:
        return str(e)


def insert_linked(conn, data):
    try:
        cur = conn.cursor()
        sql = 'insert into linked (symptoms, patient_id, doctor_id) values (?,?,?)'
        cur.execute(sql, data)
        conn.commit()
        return True
    except Exception as e:
        return str(e)


def get_all_doctors(conn):
    cur = conn.cursor()
    cur.execute("select * from doctors")
    rows = cur.fetchall()
    return rows


def get_all_patients(conn):
    cur = conn.cursor()
    cur.execute("select * from patients")
    rows = cur.fetchall()
    return rows


def get_all_linked(conn):
    cur = conn.cursor()
    cur.execute("select * from linked")
    rows = cur.fetchall()
    return rows


def get_doctor(conn, username, password):
    cur = conn.cursor()
    cur.execute(
        'SELECT * FROM doctors WHERE username= "{}" AND password="{}"'.format(username, password))
    rows = cur.fetchall()
    return rows


def get_patient(conn, username, password):
    cur = conn.cursor()
    cur.execute(
        'SELECT * FROM patients WHERE username= "{}" AND password="{}"'.format(username, password))
    rows = cur.fetchall()
    return rows


def get_doc_public_key_by_id(conn, id):
    cur = conn.cursor()
    cur.execute(
        'SELECT public_key FROM doctors WHERE id= "{}"'.format(id))
    rows = cur.fetchone()
    return rows[0]


def get_doctor_by_id(conn, id):
    cur = conn.cursor()
    cur.execute('SELECT * FROM doctors WHERE id= "{}" '.format(id))
    rows = cur.fetchall()
    return rows


def get_patient_by_id(conn, id):
    cur = conn.cursor()
    cur.execute('SELECT * FROM patients WHERE id= "{}"'.format(id))
    rows = cur.fetchall()
    return rows


def get_linked_by_doctor_id(conn, id):
    cur = conn.cursor()
    cur.execute('SELECT * FROM linked WHERE doctor_id= "{}"'.format(id))
    rows = cur.fetchall()
    return rows


def create_tables(conn):
    cur = conn.cursor()
    cur.execute(
        'CREATE TABLE linked (id INTEGER PRIMARY KEY AUTOINCREMENT, patient_id INTEGER, doctor_id INTEGER, symptoms TEXT)')
    cur.execute('CREATE TABLE patients (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, contact TEXT, email TEXT, username TEXT, password TEXT)')
    cur.execute('CREATE TABLE doctors (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, contact TEXT, email TEXT, username TEXT, password TEXT, speciality TEXT, experience INT)')


def drop_table(conn, table):
    cur = conn.cursor()
    cur.execute('drop table {}'.format(table))
