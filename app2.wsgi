import sys
import os
import threading
import time
import schedule

sys.path.append('C:/packageoffline/Odisha_Gramya_Bank_App - V1/Odisha_Gramya_Bank_App - V1/Odisha_Gramya_Bank_App - SQLMain Code')
from app import app as application, verify_tenpercent_data, sftp_server, detltaADupdate, For_AD_USERNAME_update, For_AD_PASSWORD_update, AD_SERVER, AD_BASE_DN, verifyFilesExists



schedule.every().day.at("23:00").do(verify_tenpercent_data)

schedule.every(1).minutes.do(detltaADupdate,For_AD_USERNAME_update,For_AD_PASSWORD_update)


def run_closed_alerts_loop():
    while True:
        schedule.run_pending()
        time.sleep(1)



closed_while_thread = threading.Thread(target=run_closed_alerts_loop)
closed_while_thread.start()

verification_thread = threading.Thread(target=verifyFilesExists)
verification_thread.start()


ftp_while_thread = threading.Thread(target=sftp_server)
ftp_while_thread.start()