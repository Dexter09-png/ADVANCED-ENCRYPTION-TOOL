# ADVANCED-ENCRYPTION-TOOL

*COMPANY*: CODTECH IT SOLUTIONS

*NAME*: GAIKWAD SANITA SANJAY

*INTERN ID*: CT04DL698

*DOMAIN*: CYBER SECURITY & ETHICAL HACKING

*DURATION*: 4 WEEKS

*MENTOR*: NEELA SANTOSH

*DISCRIPTION*:

I developed a secure file encryption and decryption tool in Python using the AES-256 encryption standard. The objective behind creating this application was to implement a reliable, user-friendly utility for protecting sensitive data through strong cryptographic techniques. This tool is particularly suitable for individuals, professionals, or small organizations that need to safeguard confidential files locally.

The application uses the Advanced Encryption Standard (AES) with a 256-bit key in Cipher Block Chaining (CBC) mode, a widely trusted and secure encryption method. To derive a strong key from a user-provided password, I’ve implemented PBKDF2 (Password-Based Key Derivation Function 2) using SHA-256, along with a random salt and 100,000 iterations. This ensures that each encryption operation produces a unique key, even when the same password is used. I also generate a 16-byte Initialization Vector (IV) to strengthen the security of CBC mode.

When a user chooses to encrypt a file, the tool prompts for the input and output file paths and then confirms the password. The input file is read, padded using PKCS7 padding to meet the AES block size requirement, and encrypted. The final output includes the salt, IV, and encrypted data, all written in binary format to the output file. The decryption process reverses this by extracting the salt and IV, regenerating the key using the same password, and decrypting the content after proper unpadding. Error handling is included to ensure graceful failure if the password is incorrect or the file is corrupted.

I ran and tested the code on both Trea and Python’s IDLE environments. These platforms provided a stable and clear interface for debugging and refining the logic, especially during the development of file handling and encryption operations.

This application has a range of real-world applications. It can be used to secure sensitive documents such as financial records, academic files, legal agreements, or research data. For example, small businesses can use it to protect financial reports before transmitting them over unsecured channels. Researchers and students can safeguard project files when sharing them with external collaborators. Freelancers can encrypt client deliverables before handoff to ensure confidentiality.

In the process of building this tool, I referred to several high-quality technical resources. GeeksforGeeks helped me understand the theory behind AES and PBKDF2. Real Python offered valuable insight into best practices for file and password handling in Python. I also referred to the Cryptography library documentation (cryptography.io) to correctly implement padding, cipher initialization, and secure key generation. Stack Overflow was instrumental in resolving several implementation challenges, especially related to padding errors and file encoding issues.

Creating this encryption tool not only deepened my understanding of cryptographic principles but also strengthened my ability to apply secure coding practices in practical scenarios. I believe this project demonstrates a solid grasp of applied cryptography and the importance of building secure tools with usability in mind.

*OUTPUT*

![Image](https://github.com/user-attachments/assets/7890bb93-0c3b-41eb-80ed-508166482607)

![Image](https://github.com/user-attachments/assets/675d6ed2-dcaa-4498-979b-8c1d26150b41)
