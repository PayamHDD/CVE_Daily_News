from Config.settings import Token
import mysql.connector



class DBConnection():
    CREATE_DB = "CREATE DATABASE vulninfo"
    CREATE_TABLE_USER = """CREATE TABLE telegram_users (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    chat_id BIGINT NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );"""

    CREATE_TABLE_PRODUCT = """CREATE TABLE products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );"""

    CREATE_TABLE_SUBSCRIPTION = """CREATE TABLE subscriptions (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    product_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    UNIQUE KEY uniq_user_product (user_id, product_id),

    FOREIGN KEY (user_id)
        REFERENCES telegram_users(id)
        ON DELETE CASCADE,

    FOREIGN KEY (product_id)
        REFERENCES products(id)
        ON DELETE CASCADE
    );"""


    def __init__(self):
        self.db_user = Token.DB_USER
        self.db_password = Token.DB_Token
        self.cnx = mysql.connector.connect(user=self.db_user, password=self.db_password,
                              host='127.0.0.1',
                              database='vulninfo')


    def insertData(self, chat_id, product):
        cursor = self.cnx.cursor()
        u_command = "INSERT IGNORE INTO telegram_users (chat_id) VALUES (%s);"
        cursor.execute(u_command, (chat_id,))
        p_command = "INSERT IGNORE INTO products (name) VALUES (%s);"
        cursor.execute(p_command, (product,))
        sub_command = """INSERT IGNORE INTO subscriptions (user_id, product_id) 
        SELECT u.id, p.id FROM telegram_users u, products p 
        WHERE u.chat_id = %s AND p.name = %s;"""
        cursor.execute(sub_command, (chat_id, product))

        self.cnx.commit()
        cursor.close()


    def deleteData(self, chat_id, product):
        cursor = self.cnx.cursor()
        d_command = """DELETE s FROM subscriptions s 
        JOIN telegram_users u ON s.user_id = u.id JOIN products p ON s.product_id = p.id 
        WHERE u.chat_id = %s AND p.name = %s;"""

        cursor.execute(d_command, (chat_id, product))
        self.cnx.commit()
        cursor.close()


    def notifQuery(self, product):
        cursor = self.cnx.cursor()
        n_command = """SELECT u.chat_id
        FROM subscriptions s
        JOIN telegram_users u ON s.user_id = u.id
        JOIN products p ON s.product_id = p.id
        WHERE p.name = %s;"""

        cursor.execute(n_command, (product,))
        #self.cnx.commit() select does not need commit!
        rows = cursor.fetchall()
        cursor.close()
        return rows
    

    def close(self):
        self.cnx.close()