# Codebase Analysis Report

## Overview
This report details the analysis of the provided Android application codebase, focusing on payment-related logic, purchase bypass, and license verification mechanisms. The analysis primarily targeted the native libraries (`.so` files) due to the presence of a packer (`libjiagu.so`) which obfuscates the Java bytecode.

## Key Findings

### 1. Protection Mechanism
The application is protected by **Qihoo 360 Jiagu** packer, evidenced by the presence of `assets/libjiagu.so` and `assets/libjiagu_a64.so`. This packer encrypts the main DEX file, making static analysis of the Java code (`classes.dex`) difficult without unpacking.

### 2. Native Library Analysis
We analyzed several native libraries for payment and license-related strings and logic.

#### `libeffect.so` (Effect SDK)
This library contains significant logic related to premium features (likely video effects) and their licensing.

*   **Strings Found**:
    *   `{en} License unauthorized functions, please check whether to purchase corresponding functions`
    *   `{en} The request function does not match, please check whether to purchase the corresponding function`
*   **Exported Functions**: The library exports multiple functions explicitly named for license checking:
    *   `bef_effect_ai_check_online_license`
    *   `bef_effect_ai_check_license`
    *   `bef_effect_ai_check_license_function`
    *   `bef_effect_ai_face_check_license`
    *   `Java_com_effectsar_labcv_effectsdk_OnlineLicense_GetAuthMsg`

*   **Disassembly Analysis**:
    *   Target function: `bef_effect_ai_check_license` (Address: `0x4fd8f8` in `lib/arm64-v8a/libeffect.so`).
    *   The function performs a check (likely calling internal validation functions).
    *   If the check fails (non-zero return from internal call), it sets an error code (e.g., `0x2b0010`) and returns.
    *   **Logic Error / Bypass Opportunity**: The license check is performed client-side within this exported function. An attacker could potentially hook or patch this function to always return success (0), effectively bypassing the purchase requirement for effects.

#### `libRongIMLib.so` (IM Library)
*   **Strings Found**: `payment gateway capabilities`.
*   **Analysis**: This string is present in the `.rodata` section and referenced in the code. However, it appears to be part of a capability check for the messaging protocol rather than the core payment processing logic. The core payment logic is likely handled by the server or a different component.

#### `libZegoExpressEngine.so` (Audio/Video Engine)
*   **Strings Found**: `payment gateway capabilities`, `money_get error`.
*   **Exported Functions**:
    *   `zego_express_set_license`
    *   `zego_express_enable_check_poc`
*   **Analysis**: This library also has client-side license management. The `set_license` function suggests that the app sets a license key (likely fetched from the server) to enable the engine.

## Logic Error & Exploitation Scenario

The primary logic error identified is the **reliance on client-side native functions for license verification** in `libeffect.so`.

### Theoretical Bypass
To bypass the payment/license check for effects:
1.  **Target**: `bef_effect_ai_check_license` in `libeffect.so`.
2.  **Action**: Patch the function prologue to immediately return success.
3.  **Patch**:
    ```assembly
    mov w0, #0      ; Return code 0 (Success)
    ret             ; Return
    ```
    Opcode (ARM64 Little Endian): `00 00 80 52 C0 03 5F D6`
4.  **Result**: The app would believe the license is valid and unlock the premium effects.

## Recommendations
To mitigate these risks:
1.  **Server-Side Validation**: Move critical license checks to the server. The client should only receive a signed token that unlocks features, which is verified by the server during use (if possible) or by the engine using a secure channel.
2.  **Obfuscation**: Rename exported functions in native libraries to non-descriptive names (e.g., `a`, `b`, `c`) to make reverse engineering harder.
3.  **Integrity Checks**: Implement runtime integrity checks to detect if the native library has been patched or hooked.
4.  **Packer Configuration**: Ensure the packer also protects the native libraries (`.so` files), not just the DEX file.

## Tools Used
*   `capstone` (Python library) for disassembly.
*   Custom Python scripts (`analyze_so.py`, `disasm_range.py`) for targeted analysis.
*   `objdump` for symbol table inspection.
