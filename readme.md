
# 🧩 Stack Integrity Check  
### Universal Call Stack Integrity Detection Solution (SleepMask / ROP / VEH / Stack Spoofing Detection)

This project aims to provide a **universal call stack integrity verification method** for detecting various advanced evasion techniques, including SleepMask, call stack spoofing, ROP chain construction, and encrypted stacks.

Unlike traditional signature scanning, this method is based on **authenticity verification of the call stack**, inherently offering universal applicability and robustness against variants. It effectively counters advanced evasion techniques such as obfuscated stacks.

---

## 📌 Background

Since the emergence of tools like **DuckMemoryScan / BeaconEye** that locate Beacons by traversing the stack, attackers have increasingly adopted various stack obfuscation techniques, such as:
ALL İMG
<img width="912" height="681" alt="1" src="https://github.com/user-attachments/assets/305387cf-ce95-466d-bfcb-1272f652cf18" />
<img width="1093" height="1085" alt="6" src="https://github.com/user-attachments/assets/8b39fc9a-fa1a-46be-9a75-0e0fb6ca765a" />
<img width="906" height="1090" alt="7" src="https://github.com/user-attachments/assets/e0b2b0c2-f3fb-4075-9e0a-8a925ed8216a" />
<img width="1720" height="925" alt="8" src="https://github.com/user-attachments/assets/fabd9d0d-d4c2-413a-99b3-22a1318f8dd2" />
![9](https://github.com/user-attachments/assets/f60a64cd-69df-4005-b5c0-b22bb196c148)
<img width="922" height="702" alt="2" src="https://github.com/user-attachments/assets/4abc02d7-e7e4-4ce6-aa11-7d779c1e02a5" />
<img width="1310" height="399" alt="3" src="https://github.com/user-attachments/assets/00810a6b-fd87-476a-8cb4-36ce6a7faa9b" />
<img width="1236" height="1075" alt="4" src="https://github.com/user-attachments/assets/090dd724-1f5b-4a0f-bf65-b7b1dc713b2b" />
<img width="1345" height="1125" alt="5" src="https://github.com/user-attachments/assets/71e4a48e-a022-46f0-a0f5-943d426c4880" />

- SleepMask (Sleep-Time Call Stack Forgery)
- ROP Constructing a Fake Call Chain
- VEH-based Stack Spoofing
- Randomization / Encrypted Stack
- Shadow stack bypass

Typical manifestations include:

🔹 Stack during normal operation (actual call chain)
```
Actual call stack -> Valid return address chain
```

🔹 Sleep + Mask: Forged Return Address Chain in the Stack
```
faked call stack -> ROP frames -> junk frames
```

Most stack-based scanning detection tools fail outright when confronted with forged stacks. Forged stacks return address chains.

---

## 🧭 Issues with Existing Detection Methods

✔ VirtualProtect Monitoring (infinityHook / VTI)  
- **Advantages**: Fast, accurate  
- **Disadvantages**: High resource consumption, requires logging all memory permission changes

✔ Feature Scanning  
- Such as scanning `unbacked stack → Sleep` or SleepMask features  
- **Advantages**: High accuracy in specific scenarios  
- **Disadvantages**: Easily bypassed by modified code

✔ CET (Control-flow Enforcement Technology)
- **Advantages**: Hardware-level, accurate, fast  
- **Disadvantages**: Unavailable without hardware support

---

🛠 General Approach: Stack Integrity Check

The core concept is based on a fundamental fact:

> In the vast majority of real call stacks, return addresses can be logically linked through `call` instructions.  
> That is: The current return address should correspond to the preceding call statement.

By verifying whether this chain is natural, continuous, and logical, one can determine whether the stack has been forged.

---

## 🔬 Workflow (Core Logic)

### 1. Traverse the Stack
Use `StackWalk64` to obtain the 64-bit call stack.

### 2. Pattern Matching for Exception Stacks
- SleepMask often encrypts/obfuscates the stack  
- Determine if it's a valid instruction region by reading the code within the stack

Inspection Method:

- Extract 8 instructions near each stack address  
- Determine if they constitute valid, contiguous machine code  
- If invalid, the stack may be counterfeit  
Code checks whether the region contains valid instructions

---

3. Match Call Instructions and Verify Return Addresses

Match the following instruction types:

- `call imm`
- `call reg`
- `call mem`

Then verify:

```
call_next == return_address ?
```

If not true, it indicates the call chain integrity is broken → highly suspicious.

---

# 📈 Detection Effectiveness

Testing against common stack spoofing frameworks:

| Technique | Detection Result |
|------|----------|
| Stack encryption / junk frames | ✔ |
| Ekko stack spoofer | ✔ |
| SlientMoonWalker | ✔ |
| Cronos | ✔ |
| Various SleepMask variants | ✔ |

Theoretically, all stack manipulation-based mechanisms can be detected.

---

🚀 Future Expansion Potential

Stack + Instruction Matching can be further applied to:

- Unknown shellcode detection
- Shellcode auto-tagging
- ROP chain identification
- Dynamic malicious behavior detection
- Hidden execution flow prediction

More details may be disclosed in the future.

---

# 📄 Technical Keywords

- Stack Integrity Validation  
- SleepMask Detection  
- ROP Call Chain Verification  
- StackWalk64  
- Call Pattern Matching  
- Anti-Evasion  
- Windows Internals  

