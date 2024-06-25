import pyodbc
import json

# Database connection details
serverIP2 = '10.40.16.189'
userSQL2 = 'OGBBANK'
pwdSQL2 = 'root12345'
database_name = 'ticketid'

try:
    sql_server_connection = pyodbc.connect(f"Driver={{SQL Server}};SERVER={serverIP2};Database={database_name};UID={userSQL2};PWD={pwdSQL2}")


    print("Connected to SQL Server successfully.")
except pyodbc.Error as e:
    print("Error connecting to SQL Server:", e)

# Create a cursor
cursor = sql_server_connection.cursor()

# Check if the database exists
cursor.execute("IF DB_ID(?) IS NULL BEGIN SELECT 0 END ELSE BEGIN SELECT 1 END", database_name)
db_exists = cursor.fetchone()[0]

if not db_exists:
    cursor.execute(f"CREATE DATABASE [{database_name}]")
    print(f"Database '{database_name}' created successfully.")
else:
    print(f"Database '{database_name}' already exists.")

cursor.close()

try:
    sql_server_connection = pyodbc.connect(f"Driver={{SQL Server}};SERVER={serverIP2};Database={database_name};UID={userSQL2};PWD={pwdSQL2}")
    print(f"Connected to the '{database_name}' database successfully.")
except pyodbc.Error as e:
    print("Error connecting to the database:", e)

# Recreate the cursor
cursor = sql_server_connection.cursor()

# Load data from JSON file
with open('Query_Threshold_new.json', 'r') as file:
    data = json.load(file)

    for alert in data.get('alerts', []):
        if isinstance(alert, dict):
            code = alert.get('code')
            if not code:
                continue
            # code_prefix = code[:2].upper()
            code_prefix = code.split('_')[0].upper()
            current_values_json = json.dumps(alert['Current_values'])
            threshold_type = alert.get('Threshold_Type', 'Unknown')  


            cursor.execute("IF OBJECT_ID('Thresholds', 'U') IS NULL BEGIN SELECT 0 END ELSE BEGIN SELECT 1 END")
            table_exists = cursor.fetchone()[0]

            if not table_exists:
                create_table_query = """
                CREATE TABLE Thresholds (
                    Threshold_Type VARCHAR(50),
                    code VARCHAR(50),
                    Alert_title VARCHAR(255),
                    Current_values NVARCHAR(MAX),
                    Previous_values NVARCHAR(MAX)
                )
                """
                cursor.execute(create_table_query)
                print("Table 'Thresholds' created successfully.")

            find_query = "SELECT * FROM Thresholds WHERE code = ?"
            cursor.execute(find_query, (code,))
            existing_document = cursor.fetchone()

            if existing_document:
                previous_values = existing_document.Previous_values if existing_document.Previous_values else None
                update_query = """
                UPDATE Thresholds
                SET
                    Alert_title = ?,
                    Current_values = ?,
                    Previous_values = ?,
                    Threshold_Type = ?

                WHERE code = ?
                """
                cursor.execute(update_query, (code_prefix, alert['Alert_title'], current_values_json, previous_values,threshold_type, code))
                print(f"Document updated with code: {code}")
            else:
                insert_query = """
                INSERT INTO Thresholds ( code, Alert_title, Current_values, Previous_values,Threshold_Type)
                VALUES (?, ?, ?, ?,?)
                """
                cursor.execute(insert_query, ( code, alert['Alert_title'], current_values_json, None,threshold_type))
                print(f"Document inserted with code: {code}")

sql_server_connection.commit()
sql_server_connection.close()



