import os
import time
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

def capture_screenshots():
    os.makedirs("screenshots", exist_ok=True)

    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--window-size=1400,900")

    driver = webdriver.Chrome(options=options)
    try:
        print("[screenshots] Navigating to login page...")
        driver.get("http://127.0.0.1:5000/login")
        WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.NAME, "username")))

        print("[screenshots] Submitting login credentials...")
        driver.find_element(By.NAME, "username").send_keys("admin")
        driver.find_element(By.NAME, "password").send_keys("Admin1234567!")
        driver.find_element(By.TAG_NAME, "form").submit()

        print("[screenshots] Waiting for dashboard...")
        WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.ID, "stat-packets")))
        time.sleep(2)  # allow initial api fetch to complete

        dashboard_png = os.path.abspath("screenshots/dashboard.png")
        driver.save_screenshot(dashboard_png)
        print(f"[screenshots] Saved dashboard screenshot to {dashboard_png}")

        print("[screenshots] Opening alert details modal via JS...")
        WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.CLASS_NAME, "btn-details")))
        driver.execute_script("document.querySelector('.btn-details').click();")
        time.sleep(1.5)

        modal_png = os.path.abspath("screenshots/alert_details.png")
        driver.save_screenshot(modal_png)
        print(f"[screenshots] Saved alert details screenshot to {modal_png}")

    finally:
        driver.quit()
        print("[screenshots] Browser closed.")

if __name__ == "__main__":
    capture_screenshots()
