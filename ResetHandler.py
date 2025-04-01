from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import os
import subprocess
import time


def reset_eero():
    try:
        subprocess.check_output(["sudo", "nmcli","dev", "wifi", "connect", "pirwani-verizon", "password", "correctPassword"])
        time.sleep(1)
        subprocess.check_output(["kasa", "--host", "192.168.1.151", "--username", "ddar203@gmail.com", "--password", "nywciZ-2junze-vuspiv", "off"])
        time.sleep(2)
        subprocess.check_output(["kasa","--host","192.168.1.151","--username","ddar203@gmail.com","--password","nywciZ-2junze-vuspiv","on"])
    except:
        print("reboot failed..")
        return False
    return True
        
def reset_ASUS1800S():
    try:
        # subprocess.check_output(["sudo", "service","NetworkManager","start"])
        # time.sleep(5)
        subprocess.check_output(["sudo", "nmcli","dev", "wifi", "connect", "Pirwani-ASUS-1800S", "password", "correctPassword"])
        time.sleep(1)

        chrome_options = Options()
        chrome_options.add_argument("--headless")  # Run in headless mode
        chrome_options.binary_location = "/home/pirwani/Desktop/chrome-linux64/chrome"
        chrome_options.add_argument("--no-sandbox")             # Bypass OS security model
        chrome_options.add_argument("--disable-dev-shm-usage")  # Overcome limited resource problems
        # chrome_options.add_argument("--disable-gpu")            # Disable GPU hardware acceleration
        # chrome_options.add_argument("--window-size=1920x1080")  #  # Fix DevToolsActivePort error



        driver = webdriver.Chrome(service=Service("./chromedriver"), options=chrome_options)

        driver.get('http://www.asusrouter.com/Main_Login.asp')

        time.sleep(2)

        username_field = driver.find_element(By.ID, 'login_username')
        password_field = driver.find_element(By.NAME, 'login_passwd')

        username_field.send_keys('pirwani')
        password_field.send_keys('testbed')


        login_button = driver.find_element(By.CLASS_NAME, 'button')
        login_button.click()

        time.sleep(10)
        reboot_button = driver.find_element(By.XPATH, "//div[contains(@class, 'titlebtn')]/span[text()='Reboot']")
        reboot_button.click()
        WebDriverWait(driver, 10).until(EC.alert_is_present())

        alert = driver.switch_to.alert

        alert.accept()

        time.sleep(5)
        driver.quit()
    except KeyboardInterrupt:
        raise KeyboardInterrupt
    except:
        print("reboot failed")
        return False
    # subprocess.check_output(["sudo", "airmon-ng", "check", "kill"])
    # time.sleep(2)
    return True

def reset_ASUSTUF():
    try:
        # subprocess.check_output(["sudo", "service","NetworkManager","start"])
        # time.sleep(5)
        subprocess.check_output(["sudo", "nmcli","dev", "wifi", "connect", "pirwani-ASUS-TUF", "password", "correctPassword"])
        time.sleep(1)

        chrome_options = Options()
        chrome_options.add_argument("--headless")  # Run in headless mode
        chrome_options.binary_location = "/home/pirwani/Desktop/chrome-linux64/chrome"
        chrome_options.add_argument("--no-sandbox")             # Bypass OS security model
        chrome_options.add_argument("--disable-dev-shm-usage")  # Overcome limited resource problems
        # chrome_options.add_argument("--disable-gpu")            # Disable GPU hardware acceleration
        # chrome_options.add_argument("--window-size=1920x1080")  #  # Fix DevToolsActivePort error
        chrome_options.add_argument('--ignore-certificate-errors')



        driver = webdriver.Chrome(service=Service("./chromedriver"), options=chrome_options)

        driver.get('http://www.asusrouter.com/Main_Login.asp')

        time.sleep(5)

        username_field = driver.find_element(By.XPATH, '//input[@placeholder="Username"]')
        password_field = driver.find_element(By.NAME, 'login_passwd')

        username_field.send_keys('pirwani')
        password_field.send_keys('testbed')


        login_button = driver.find_element(By.ID, 'button')
        login_button.click()

        time.sleep(10)
        reboot_button = driver.find_element(By.ID, 'reboot_status')
        reboot_button.click()
        WebDriverWait(driver, 10).until(EC.alert_is_present())

        alert = driver.switch_to.alert

        alert.accept()

        time.sleep(5)
        driver.quit()
    except KeyboardInterrupt:
        raise KeyboardInterrupt
    except:
        print("reboot failed")
        return False
    # subprocess.check_output(["sudo", "airmon-ng", "check", "kill"])
    # time.sleep(2)
    return True

def reset_TPLink0C78():
    try:
        # subprocess.check_output(["sudo", "service","NetworkManager","start"])
        # time.sleep(5)
        subprocess.check_output(["sudo", "nmcli","dev", "wifi", "connect", "Pirwani-TP-Link_0C78", "password", "correctPassword"])
        time.sleep(1)

        chrome_options = Options()
        chrome_options.add_argument("--headless")  # Run in headless mode
        chrome_options.binary_location = "/home/pirwani/Desktop/chrome-linux64/chrome"
        chrome_options.add_argument("--no-sandbox")             # Bypass OS security model
        chrome_options.add_argument("--disable-dev-shm-usage")  # Overcome limited resource problems
        # chrome_options.add_argument("--disable-gpu")            # Disable GPU hardware acceleration
        # chrome_options.add_argument("--window-size=1920x1080")  #  # Fix DevToolsActivePort error



        driver = webdriver.Chrome(service=Service("./chromedriver"), options=chrome_options)

        driver.get('http://tplinkwifi.net')

        time.sleep(7)

        password_field = driver.find_element(By.XPATH, '//input[@type="password"]')

        password_field.send_keys('testbed1')


        login_button = driver.find_element(By.XPATH, '//a[@title="LOG IN"]')
        login_button.click()

        time.sleep(5)
        driver.get('http://tplinkwifi.net/webpages/index.html?t=43619936#reboot')
        time.sleep(5)
        reboot_button = driver.find_element(By.XPATH, '//a[@title="REBOOT"]')
        reboot_button.click()

        time.sleep(5)
        driver.quit()
    except KeyboardInterrupt:
        raise KeyboardInterrupt
    except:
        print("reboot failed")
        return False
    # subprocess.check_output(["sudo", "airmon-ng", "check", "kill"])
    # time.sleep(2)
    return True

def reset_TPLinkCD7A():
    try:
        # subprocess.check_output(["sudo", "service","NetworkManager","start"])
        # time.sleep(5)
        subprocess.check_output(["sudo", "nmcli","dev", "wifi", "connect", "pirwani-TP-Link_CD7A", "password", "correctPassword"])
        time.sleep(1)

        chrome_options = Options()
        chrome_options.add_argument("--headless")  # Run in headless mode
        chrome_options.binary_location = "/home/pirwani/Desktop/chrome-linux64/chrome"
        chrome_options.add_argument("--no-sandbox")             # Bypass OS security model
        chrome_options.add_argument("--disable-dev-shm-usage")  # Overcome limited resource problems
        # chrome_options.add_argument("--disable-gpu")            # Disable GPU hardware acceleration
        # chrome_options.add_argument("--window-size=1920x1080")  #  # Fix DevToolsActivePort error



        driver = webdriver.Chrome(service=Service("./chromedriver"), options=chrome_options)

        driver.get('http://tplinkwifi.net')

        time.sleep(7)

        password_field = driver.find_element(By.XPATH, '//input[@type="password"]')

        password_field.send_keys('correctPassword1')


        login_button = driver.find_element(By.XPATH, '//a[@title="LOG IN"]')
        login_button.click()

        time.sleep(5)
        driver.get('http://tplinkwifi.net/webpages/index.html?t=d6aa95cb#reboot')
        time.sleep(5)
        reboot_button = driver.find_element(By.XPATH, '//a[@title="REBOOT"]')
        reboot_button.click()

        time.sleep(5)
        driver.quit()
    except KeyboardInterrupt:
        raise KeyboardInterrupt
    except:
        print("reboot failed")
        return False
    # subprocess.check_output(["sudo", "airmon-ng", "check", "kill"])
    # time.sleep(2)
    return True

def reset_Verizon():
    try:
        # subprocess.check_output(["sudo", "service","NetworkManager","start"])
        # time.sleep(5)
        subprocess.check_output(["sudo", "nmcli","dev", "wifi", "connect", "pirwani-verizon", "password", "correctPassword"])
        time.sleep(1)

        chrome_options = Options()
        chrome_options.add_argument("--headless")  # Run in headless mode
        chrome_options.binary_location = "/home/pirwani/Desktop/chrome-linux64/chrome"
        chrome_options.add_argument("--no-sandbox")             # Bypass OS security model
        chrome_options.add_argument("--disable-dev-shm-usage")  # Overcome limited resource problems
        chrome_options.add_argument('--ignore-certificate-errors')

        # chrome_options.add_argument("--disable-gpu")            # Disable GPU hardware acceleration
        # chrome_options.add_argument("--window-size=1920x1080")  #  # Fix DevToolsActivePort error



        driver = webdriver.Chrome(service=Service("./chromedriver"), options=chrome_options)

        driver.get('http://mynetworksettings.com')

        time.sleep(5)

        password_field = driver.find_element(By.XPATH, '//input[@type="password"]')

        password_field.send_keys('testbed1')


        login_button = driver.find_element(By.CLASS_NAME, 'btn-primary')
        login_button.click()

        time.sleep(5)
        driver.get('http://mynetworksettings.com/#/adv/system/reboot')
        time.sleep(5)
        
        reboot_button = driver.find_element(By.XPATH, '//input[@value="Reboot Device"]')
        reboot_button.click()
        time.sleep(5)
        
        reboot_confirm = driver.find_element(By.XPATH, '//button[@aria-label="Reboot"]')
        reboot_confirm.click()

        time.sleep(5)
        driver.quit()
    except KeyboardInterrupt:
        raise KeyboardInterrupt
    except:
        print("reboot failed")
        return False
    # subprocess.check_output(["sudo", "airmon-ng", "check", "kill"])
    # time.sleep(2)
    return True