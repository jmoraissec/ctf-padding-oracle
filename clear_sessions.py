import os
import time

SESSION_FILE_DIR = '/app/flask_session'

def clear_sessions():
    current_time = time.time()
    for filename in os.listdir(SESSION_FILE_DIR):
        file_path = os.path.join(SESSION_FILE_DIR, filename)
        if os.path.isfile(file_path):
            file_age = current_time - os.path.getmtime(file_path)
            if file_age > (30*60): #seconds
                os.remove(file_path)

if __name__ == '__main__':
    clear_sessions()