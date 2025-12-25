# Dragon Shell 🐉

## Overview

**Dragon Shell** is a custom Unix-like command-line shell written in C.  
It supports interactive command execution, job control, signal handling, input/output redirection, background processes, and single-stage piping.

This project demonstrates core operating system concepts such as:
- Process creation and management
- Signal handling
- Foreground and background job control
- File descriptor manipulation
- Inter-process communication using pipes

The shell is designed for Linux / Unix-based systems and is implemented using low-level POSIX system calls.

---

## Features

### Built-in Commands
- `pwd` — Print the current working directory
- `cd <dir>` — Change the current working directory
- `jobs` — List background and stopped jobs
- `exit` — Exit the shell and terminate active jobs

### External Command Execution
- Launches programs using `fork()` and `execv()`
- Supports absolute paths (e.g., `/bin/ls`)

### Job Control
- Foreground and background execution (`&`)
- Tracks running (`R`) and stopped (`T`) jobs
- Handles `Ctrl+C` (SIGINT) and `Ctrl+Z` (SIGTSTP)
- Proper cleanup of terminated jobs using `SIGCHLD`

### I/O Redirection
- Input redirection: `< infile`
- Output redirection: `> outfile`

### Pipes
- Supports **single pipe** execution:
  ```bash
  /bin/ls | /usr/bin/wc
