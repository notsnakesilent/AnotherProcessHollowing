# Another Process Hollowing
Explanation and POC of the Process Hollowing (Windows) technique, commonly used by malware to bypass security systems

A complete explanation of the technique is available in 
<p align="center">
  <a href="docs/technique_ES.md">Español</a> |
  <a href="docs/technique_EN.md">English</a>
</p>

## What is Process Hollowing?
Process Hollowing is a sophisticated **evasion technique** widely used by modern malware to:
- Execute malicious code under the guise of legitimate processes
- Evade intrusion detection and prevention systems
- Maintain persistence on compromised systems

**In essence**: a legitimate process is created in a suspended state, its memory content is hollowed out, and replaced with malicious code. When the process is resumed, the malicious code runs with the privileges and appearance of the original process.

## For Educational Purposes Only
This repository contains:
- **Detailed explanation** of the Process Hollowing technique (English and Spanish)
- **Complete source code** for a Proof of Concept (PoC)

## How It Works
The technique is divided into several critical steps:
1. **Creation**: A legitimate process (like notepad.exe) is created in a suspended state
2. **Disassembly**: The PEB (Process Environment Block) is obtained and disassociated
3. **Hollowing**: The original process memory is freed
4. **Injection**: Malicious code is written into the freed memory space
5. **Reconstruction**: Entry point is reconfigured and context restored
6. **Execution**: The process is resumed, now running the malicious code

## Cybersecurity Applications
- **Malware research**: Understanding how advanced threats operate
- **Penetration testing**: Evaluating defenses against evasion techniques
- **Defense development**: Creating detection systems for this technique

## Repository Structure
```
AnotherProcessHollowing/
├── src/
│   ├── main.cpp           # Source Code
├── docs/                  
│   ├── technique_ES.md    # Detailed explanation in Spanish
│   └── technique_EN.md    # Detailed explanation in English
├── README.md              # README English
└── README_ES.md           # README Spanish
```
