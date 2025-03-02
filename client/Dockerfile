FROM kalilinux/kali-last-release

RUN apt update && apt install -y python3 netcat-openbsd metasploit-framework

COPY exploit_auth_result.py /home/exploit_auth_result.py

COPY exploit_dos.py /home/exploit_dos.py

COPY utility_address_calc.py /home/utility_address_calc.py

COPY exploit_reverse_shell.py /home/exploit_reverse_shell.py

COPY exploit_reverse_shell_clear.py /home/exploit_reverse_shell_clear.py

COPY exploit_reverse_shell_frag.py /home/exploit_reverse_shell_frag.py




