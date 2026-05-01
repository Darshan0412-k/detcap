from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page(viewport={"width": 1360, "height": 680})
    page.goto("file:///D:/AI/detcap/detcap_logo.svg")
    page.screenshot(path="detcap_logo.png", full_page=False)
    browser.close()

print("Done! detcap_logo.png saved.")