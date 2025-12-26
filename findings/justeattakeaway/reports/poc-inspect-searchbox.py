from playwright.sync_api import sync_playwright
import json

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page()

    print("Navigating to just-eat.es...")
    page.goto('https://www.just-eat.es/', wait_until='networkidle', timeout=30000)

    print("Taking screenshot...")
    page.screenshot(path='/tmp/justeat-es.png', full_page=True)
    print("Screenshot saved to /tmp/justeat-es.png")

    # Find input fields
    print("\n=== INPUT FIELDS ===")
    inputs = page.locator('input').all()
    for i, inp in enumerate(inputs[:10]):  # First 10 inputs
        try:
            placeholder = inp.get_attribute('placeholder') or ''
            name = inp.get_attribute('name') or ''
            id_attr = inp.get_attribute('id') or ''
            class_attr = inp.get_attribute('class') or ''
            print(f"Input {i}: placeholder='{placeholder}', name='{name}', id='{id_attr}', class='{class_attr[:80]}'")
        except:
            pass

    # Search for f-searchbox, fozzie, vue references
    print("\n=== SEARCHING FOR COMPONENT REFERENCES ===")
    html = page.content()

    if 'f-searchbox' in html:
        print("FOUND: f-searchbox reference in page HTML")
    else:
        print("NOT FOUND: f-searchbox")

    if 'fozzie' in html:
        print("FOUND: fozzie reference in page HTML")
    else:
        print("NOT FOUND: fozzie")

    if 'vue' in html.lower():
        print("FOUND: vue reference in page HTML")
    else:
        print("NOT FOUND: vue")

    # Look for search-related elements
    print("\n=== SEARCH-RELATED ELEMENTS ===")
    search_elements = page.locator('[class*="search"], [id*="search"], [data-test*="search"], [placeholder*="direcc"], [placeholder*="address"]').all()
    for i, el in enumerate(search_elements[:5]):
        try:
            tag = el.evaluate('el => el.tagName')
            class_attr = el.get_attribute('class') or ''
            print(f"Search element {i}: <{tag}> class='{class_attr[:100]}'")
        except:
            pass

    # Get all script sources
    print("\n=== SCRIPT SOURCES (checking for component bundles) ===")
    scripts = page.locator('script[src]').all()
    for script in scripts[:15]:
        try:
            src = script.get_attribute('src') or ''
            if 'search' in src.lower() or 'fozzie' in src.lower() or 'component' in src.lower():
                print(f"Relevant script: {src}")
        except:
            pass

    browser.close()
    print("\nDone!")
