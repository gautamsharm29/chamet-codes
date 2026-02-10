# Codebase Analysis Report

## Overview
This report details the analysis of the provided Android application codebase, focusing on payment-related logic, purchase bypass, and license verification mechanisms, with a specific investigation into "unlimited beans/coins" vulnerabilities.

## Key Findings

### 1. Protection Mechanism
The application is protected by **Qihoo 360 Jiagu** packer, evidenced by the presence of `assets/libjiagu.so` and `assets/libjiagu_a64.so`. This packer encrypts the main DEX file, making static analysis of the Java code (`classes.dex`) difficult without unpacking. The packer also likely encrypts or obfuscates string constants in the Java layer.

### 2. "Beans" and "Coins" Analysis
We performed a deep search for currency-related logic in the native libraries.

*   **`libfinauthlivenessv5.so`**: Contains references to `SafeConfigBean` and `PropertyBean`. These appear to be Java class names (likely data models) used for configuration, not necessarily the currency "bean".
*   **`libwcdb.so`**: This is the WeChat Database library (SQLite wrapper). While it handles database operations, our string analysis did not reveal specific table names like `UserBalance` or `BeanTable` in the binary strings. These table names are likely passed from the Java layer (which is packed) or obfuscated.
*   **`libeffect.so`**: Contains logic for checking "licenses" for effects. It references purchase functions but does not explicitly mention "beans" as a currency for these effects.
*   **Assets**: `assets/demo.html` and `WebViewJavascriptBridge.js` indicate a bridge between the native app and a webview. This is a common attack vector. If the "bean" purchase or reward logic is hosted in a webview, it might be susceptible to JavaScript injection or bridge manipulation (e.g., calling `submitFromWeb` with falsified data).

### 3. Payment & License Vulnerabilities (Logic Errors)

#### Client-Side License Check (`libeffect.so`)
The most significant logic error found is the **reliance on client-side native functions for license verification** in `libeffect.so`.

*   **Exported Functions**: `bef_effect_ai_check_license`, `bef_effect_ai_check_online_license`.
*   **Vulnerability**: The check appears to be performed locally. The function returns a status code.
*   **Exploitation**: An attacker could potentially patch the `bef_effect_ai_check_license` function to always return `0` (Success), effectively bypassing the requirement to purchase premium video effects.

#### "Unlimited Beans" Feasibility
Based on the analysis, "unlimited beans" is **unlikely to be achieved via simple client-side modification** if the app follows standard security practices.
*   **Server-Side Authority**: Most modern apps store currency balances on the server. The client only displays what the server reports. Modifying the local display value (e.g., in memory or a local SQLite DB) would only be a visual hack and wouldn't allow actual purchases.
*   **Potential Weakness**: If the app uses `libwcdb.so` to cache the balance and trusts this cache for offline actions or syncs it back to the server without proper validation (less common but possible), then local database modification would work. However, without access to the packed Java code or a running device to inspect the database file at runtime, this cannot be confirmed.

### 4. JavaScript Bridge
The presence of `WebViewJavascriptBridge` suggests that some business logic interacts with web content.
*   **Risk**: If the "recharge" or "earn beans" page is a webview, and it communicates completion back to the native app via `callHandler`, an attacker could inject JavaScript to invoke this handler directly, simulating a completed task or payment.

## Recommendations

1.  **Server-Side Validation**: Ensure all currency transactions (earning and spending beans) are validated and stored authoritatively on the server. Do not trust client-side reports of balance.
2.  **Secure License Checks**: Move the effect license verification to the server. Issue a signed token to the client that the native library verifies using a public key, rather than a simple boolean check function.
3.  **WebView Security**: strictly validate the origin of pages allowed to use the JavaScript bridge. Verify payloads from the webview on the server before crediting any currency.
4.  **Anti-Tampering**: Implement runtime integrity checks (e.g., checksumming the `.so` files in memory) to detect patches to `libeffect.so`.

## Tools Used
*   `capstone` (Python library) for ARM64 disassembly.
*   Custom Python scripts (`tools/analyze_so.py`, `tools/find_addr.py`) for binary analysis.
*   `strings` and `grep` for pattern matching in binary files.
