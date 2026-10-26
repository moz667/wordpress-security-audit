# Wordpress Security Audit

## Project Purpose & Motivation

### About the Project
The main goal of this project is to **gather and organize security auditing tools specifically for WordPress websites**. To simplify the installation process (and for my own convenience), all of these tools are pre-packaged and contained within a **Docker image**.

### Author's Note
Please note that **I am not a cybersecurity expert or a professional security auditor**. I am an experienced web developer who noticed a lack of easily accessible, up-to-date tools for detecting and analyzing this specific type of malware injection. 

Out of concern for this gap in the community, I decided to build this utility using my web development experience. While I have put my best efforts into making it useful and accurate, this project should be treated as a developer's helper tool rather than a certified enterprise security solution. If you require absolute security guarantees, you should always consult with a professional cybersecurity firm.

---

## Limitation of Liability & Disclaimer

### 1. Use at Your Own Risk
This software and the contained tools are provided solely for informational, educational, and assistance purposes in detecting potential malware injections in WordPress environments. The user assumes all responsibility and risk associated with the use of this Docker image.

### 2. "As-Is" Warranty
The software is provided "as is" and "as available", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and noninfringement. There is no guarantee that the tools will be uninterrupted, error-free, 100% accurate, or capable of detecting all types of malware, web shells, or vulnerabilities.

### 3. Limitation of Liability
In no event shall the authors, developers, or copyright holders be liable for any claim, damages, or other liability—whether in an action of contract, tort, or otherwise—arising from, out of, or in connection with the software, the Docker container, or the use of these tools. This includes, but is not limited to, loss of data, website downtime, profits, or business interruption caused by missed threats or false positives.

### 4. Environment Recommendation
Given the nature of malware analysis and security auditing, it is highly recommended to run this Docker container exclusively within isolated test environments or staging copies of your sites. The user is solely responsible for maintaining comprehensive backups of all databases and WordPress files prior to execution.

---

## TODO

* [ ] Search for installed malware:
  * [ ] Site code **In progress**
  * [ ] Data / Database
* [ ] Check for vulnerabilities in installed WordPress versions, plugins, and themes

