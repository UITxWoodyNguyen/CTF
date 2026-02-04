# PascalCTF 2026 🚩

Welcome to the official repository for **PascalCTF 2026**, the second edition of the cybersecurity competition organized by students from the **Blaise Pascal High School** (Reggio Emilia/Cesena, Italy).

Our goal is to create an accessible yet challenging environment for students and enthusiasts to dive into the world of Capture The Flag (CTF) competitions.

---

## 📅 Event Information

* **Date:** January 31, 2026 – February 1, 2026
* **Duration:** 24 Hours
* **Format:** Jeopardy-style
* **Website:** [ctf.pascalctf.it](https://ctf.pascalctf.it/)
* **Discord:** [Join our community](https://discord.gg/GEYETNr3Hp)

---

## 🔍 Challenge Categories

The competition featured a diverse set of challenges across 6 primary domains:

| Category | Description |
| --- | --- |
| **🌐 Web Security** | Exploiting vulnerabilities in web applications (SQLi, XSS, SSRF, etc.) |
| **🔑 Cryptography** | Breaking ciphers, attacking protocols, and mathematical puzzles. |
| **⚙️ Reverse Engineering** | Analyzing compiled binaries and understanding hidden logic. |
| **🛠️ Binary Exploitation** | Overcoming memory protections and gaining remote code execution. |
| **🤖 Artificial Intelligence** | Prompt injection, model inversion, and adversarial machine learning. |
| **🪄 Miscellaneous** | OSINT, Forensics, and logic puzzles that don't fit elsewhere. |

---

## 🏆 Final Standings

Congratulations to the top performers of this edition (out of **854 teams**):

1. 🥇 **Nukleární Okurky** (CZ)
2. 🥈 **THEM?!**
3. 🥉 **RubiyaLab** (KR)

---

## 📂 Repository Structure

```text
.
├── web/                # Web application challenges
├── crypto/             # Mathematical and cryptographic puzzles
├── pwn/                # Binary exploitation and memory corruption
├── rev/                # Reverse engineering binaries
├── ai/                 # AI-themed security challenges
├── misc/               # OSINT, Forensics, and sanity checks
└── infrastructure/      # Dockerfiles and deployment scripts

```

---

## 📜 Rules & Ethics

* **Fair Play:** No flag sharing or collaboration between teams.
* **Infrastructure:** Do not attack the CTF platform or other participants.
* **Brute Force:** Do not use automated scanners (DDoS/Fuzzing) unless specified.
* **Education:** This event is built for learning. Be respectful in all communication channels.

---

## 🛠️ Deployment (For Local Practice)

Most challenges are containerized. To run a challenge locally:

1. Navigate to the challenge directory: `cd web/challenge-name`
2. Launch with Docker: `docker-compose up --build`
3. Access the challenge at the specified local port.

---

## ✨ Contributors

A special thanks to the student team and staff who made this possible:

* **@ale18V**
* **@AlBovo** (Alan Davide Bovo)
* **@Mark-74**
* **@Giak777**
* **@dGianessiHawica**

---
