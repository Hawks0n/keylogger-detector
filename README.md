Keylogger Detector

The keylogger detector program is completely written in Python. To be honest, it’s not a fully dynamic program, but my team and I designed it so that it scans all running system processes and checks for keywords commonly used in keylogger programs.
If it encounters terms such as "pynput" (a Python library widely used in keyloggers) or filenames like "keylogger.py", the program immediately identifies the process as suspicious and can terminate it.

Key Features
Process Scanning: Detects all active processes running on the system.
Keyword-Based Detection: Flags any process containing known keylogger-related keywords.
Command-Line View: Allows the user to see the command-line arguments used by each process.

Two Termination Options:
   1. Manual Kill: User can manually terminate the flagged process.
   2.Auto Kill Switch: Automatically kills the process as soon as it is detected.


TO conclude with This project helped us understand how keyloggers operate and how they can be terminated, giving us deeper insight into basic antivirus concepts and malware detection techniques.


