#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/wait.h>

#define LINE_LENGTH 100 // Max # of characters in an input line
#define MAX_ARGS 5      // Max # of args to a command (not incl. command name)
#define MAX_LENGTH 20   // Max # of characters in an argument

// Function Declarations for builtin shell commands
int dragon_pwd(char **args);   // Print working directory - takes no args
int dragon_cd(char **args);    // Change directory - takes one arg (abs or rel path of dir)
int dragon_jobs(char **args);  // List background jobs - takes no args
int dragon_exit(char **args);  // Exit shell - takes no args

// Other function declarations
char *dragon_readline(void);
char **tokenize(char *line);
int dragon_execute(char **args, char *line);
int dragon_launch(char **args, int background, char *infile, char *outfile,  char *cmd_str);
char *join_args(char **args);
void remove_quotes(char *str);
int job_id_for(pid_t pid);
void setup_shell_signals(void);
void free_process_table(void);
void add_job(pid_t pid, char state, char *command);
void remove_job(pid_t pid);
void update_job_state(pid_t pid, char state);

// List of builtin commands, followed by their corresponding functions
char *builtin_str[] = {"pwd", "cd", "jobs", "exit"};                                     // Array of command names
int (*builtin_func[])(char **) = {&dragon_pwd, &dragon_cd, &dragon_jobs, &dragon_exit};  // Array of function pointers
int num_builtins() { return sizeof(builtin_str) / sizeof(char *); }                      // Returns number of builtin commands

// Managing Jobs
// =============
typedef struct job {
    pid_t pid;        // Process ID of the job
    char state;       // 'R' for running, 'T' for suspended
    char *command;    // Storing the command string
    struct job *next; // Pointer to the next job in the list
} job_t;                // Alias for struct job
job_t *job_list = NULL; // Head of the job linked list

void add_job(pid_t pid, char state, char *command) {
    job_t *new_job = malloc(sizeof(job_t)); // Create a new job node - allocate memory for that node
    // Allocates memory for a new job_t structure, new_job is a pointer to this memory
    new_job->pid = pid;                 // Store the process ID
    new_job->state = state;             // Store the state ('R' or 'T')
    new_job->command = strdup(command); // Make a copy of the command string
    // Insert at the beginning of the job list
    new_job->next = job_list;           // Point new job to current first job
    job_list = new_job;                 // Make new job the first job
}

void remove_job(pid_t pid) {
    // job_list is a pointer to the last added job (i.e., the head of the linked list)
    // curr is a pointer to pointer to the current job being examined - initially points to job_list
    job_t **curr = &job_list; // Pointer to pointer to the head of the job list
    while (*curr) {
        if ((*curr)->pid == pid) {
            job_t *temp = *curr;
            *curr = (*curr)->next; // Bypass the job to be removed
            free(temp->command);   // Free the command string
            free(temp);            // Free the job structure
            return;
        }
        curr = &(*curr)->next; // Move to the next job
    }
}

void update_job_state(pid_t pid, char state) {
    job_t *curr = job_list; // Start at the head of the job list
    while (curr) {
        if (curr->pid == pid) {
            curr->state = state; // Update the state of the job
            return;
        }
        curr = curr->next; // Move to the next job
    }
}

void free_process_table() {
    job_t *curr = job_list;
    while (curr != NULL) {
        job_t *temp = curr;

        // Free command
        if (temp->command != NULL) {
            free(temp->command);
        }
        // Move to the next and free node itself
        curr = curr->next;
        free(temp);
    }
    // Reset the head pointer
    job_list = NULL;
}

// Managing Jobs using Signals
// ===========================

// Handling Child State Changes
// My initial design had sigchld_handler() do the heavy work
// But since the linked list was being manipulated - it was considered unsafe
// The new design will use sigchld_handler() just to set a flag
// This flag will call the function which will do the heavy liftin
volatile sig_atomic_t sigchld_flag = 0;

void sigchld_handler(int sig) {
    // No need to check if sig == SIGCHLD, as this handler is only for SIGCHLD
    // SIGCHLD is sent to a parent process when a child process terminates or stops
    (void)sig;
    sigchld_flag = 1;
}

void reap_childeren(void) {
    int status;
    pid_t pid;

    // Use a loop to reap all terminated or stopped child processes
    // Checks for any child process that has changed state
    // waitpid(-1, &status, options) : -1 means wait for any child process
    // WNOHANG: return immediately if no child has exited
    // WUNTRACED: also return if a child has stopped (not terminated)
    // WCONTINUED: also return if a stopped child has been resumed by delivery of SIGCONT
    while ((pid = waitpid(-1, &status, WNOHANG | WUNTRACED | WCONTINUED)) > 0) {
        
        // Returns true if the child terminated normally or was terminated by a signal
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            // Process terminated
            remove_job(pid);
        } else if (WIFSTOPPED(status)) {    // Returns true if the child process was stopped by delivery of a signal
            // Process stopped              // (not terminated, cntrl-Z = SIGTSTP)
            update_job_state(pid, 'T');     // T: stopped
        } else if (WIFCONTINUED(status)) {  // Returns true if the child process was resumed by delivery of SIGCONT
            // Process continued
            update_job_state(pid, 'R');     // R: running
        }
    }
    // Note:
    // waitpid returns the process ID of the child whose state has changed,
    // or -1 if there are no children or an error occurred.
    // If no child has changed state, it returns 0 (when WNOHANG is used)
}

// Ensuring my shell doesn't die/freeze when I press Ctrl+C or Ctrl+Z; Setting up sigchld_handler
void setup_shell_signals() {
    signal(SIGINT,  SIG_IGN);  // Ignore SIGINT (Ctrl+C)
    signal(SIGTSTP, SIG_IGN);  // Ignore SIGTSTP (Ctrl+Z)
    signal(SIGTTOU, SIG_IGN);  // Ignore SIGTTOU (background process writing to terminal)
    signal(SIGTTIN, SIG_IGN);  // Ignore SIGTTIN (background process reading from terminal)

    // My shell installs sigchld_handler() once in setup_shell_signals()
    // Then on, when any child processes launched via dragon_launch() change state
    // The kernel delivers a SIGCHLD signal to the parent process (my shell)

    // Install SIGCHLD handler
    struct sigaction sa;
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;   // restart syscalls if interrupted
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }

    // Note:
    // Foreground jobs - dragon_launch() already does a blocking
    // waitpid(...), so I know when a specific child exits or stops
    // But if the child gets a signal asynchronously (eg. user sends cntrl-z)
    // the kernel also delivers SIGCHLD, and the handler should update the process table

    // Background jobs - dragon_launch() does not wait
    // Only sigchld_handler() can catch when they finish/stop/continue
    // Without it, bg jobs would never leave my process table
}

// Builtin function implementations
// ================================
int dragon_pwd(char **args) {
    char cwd[1024]; // Buffer to hold current working directory

    // pwd takes no args - if args[1] exists, it's invalid - but specifications tells us ignore it
    // if (args[1] != NULL) {return 1;}

    // getcwd(char *buf, size_t size) - returns absolute pathname of current working directory
    // returns a pointer to the buffer on success, NULL on failure

    if (getcwd(cwd, sizeof(cwd)) != NULL) {
        printf("%s\n", cwd); // format specifier %s designed for null-terminated strings
    } else {
        perror("dragonshell: pwd error");
    }
    return 1;
}

int dragon_cd(char **args) {
    // args[0] = "cd"
    if (args[1] == NULL) {
        // No argument provided to cd
        fprintf(stderr, "dragonshell: Expected argument to \"cd\"\n");
        return 1;
    } else if (args[2] != NULL) {
        // Too many arguments provided to cd
        fprintf(stderr, "dragonshell: Expected argument to \"cd\"\n");
        return 1;
    } else {
        // chdir(const char *path) - changes the current working directory to the directory specified in path
        // returns 0 on success, -1 on failure
        if (chdir(args[1]) != 0) {
            fprintf(stderr, "dragonshell: No such file or directory\n");
        }
    }
    return 1;
}

int dragon_jobs(char **args) {
    job_t *curr = job_list; // Start at the head of the job list
    // while curr is not NULL, print the job details
    while (curr) {
        printf("%d %c %s\n", curr->pid, curr->state, curr->command);
        curr = curr->next; // Move to the next job
    }
    return 1;
}

int dragon_exit(char **args) {
    // Iterate through the job list and free all allocated memory
    job_t *curr = job_list;
    while (curr != NULL) {
        if (curr->state == 'R' || curr->state == 'T') {
            // Send SIGTERM to running or stopped jobs to gracefully terminate them
            if (kill(curr->pid, SIGTERM) == -1) {
                perror("dragonshell: error terminating job");
            }
        }
        curr = curr->next;
    }
    // Free the process table
    free_process_table();
    exit(EXIT_SUCCESS); // Exit the shell
    return 0;
}

// Function to launch a program
// ============================
int job_id_for(pid_t pid) {
    job_t *curr = job_list;
    int id = 1;
    while (curr) {
        if (curr->pid == pid) {
            return id;
        }
        curr = curr->next;
        id++;
    }
    return -1;
}

char *join_args(char **args) {
    if (args == NULL || args[0] == NULL) return NULL;

    size_t len = 0;
    for (int i = 0; args[i] != NULL; i++) {
        len += strlen(args[i]) + 1; // +1 for space or '\0'
    }

    char *command = malloc(len);
    if (!command) return NULL;

    command[0] = '\0';
    for (int i = 0; args[i] != NULL; i++) {
        strcat(command, args[i]);
        if (args[i + 1] != NULL) strcat(command, " ");
    }

    return command;
}

int dragon_launch(char **args, int background, char *infile, char *outfile, char *cmd_str) {
    pid_t pid;
    int status;

    // fork() creates a copy of the current process
    // returns: 0 in the child process
    // PID (positive) in the parent process
    // -1 if error occurs

    pid = fork();

    if (pid == 0) { // Child process

        // PGIDs are stored in a kernel data structure called task_struct 
        // setpgid(pid_t pid, pid_t pgid)
        // Set the process group ID of the calling process 
        // (first 0 means use the current process's PID)
        // (second 0 means set PGID to the PID of the calling process)

        // Creates new process group using child's PID
        setpgid(0, 0); 
                
        // Restore default signal handlers in the child process
        // Child processes should handle signals normally, not inherit shell's custom handlers
        signal(SIGINT, SIG_DFL);  // Restore default handler for SIGINT
        signal(SIGTSTP, SIG_DFL); // Restore default handler for SIGTSTP

        // Background redirection
        if (background) {
            int fd = open("/dev/null", O_WRONLY);
            if (fd < 0) { perror("open /dev/null"); exit(EXIT_FAILURE); }
            dup2(fd, STDOUT_FILENO); // Redirect stdout to /dev/null
            dup2(fd, STDERR_FILENO); // Redirect stderr to /dev/null
            close(fd);
        }

        // dup2(old_fd, new_fd)
        // Makes new_fd refer to the same file as old_fd
        // if new_fd was open, it's closed first
        // close(fd)
        // dup2 creates a copy of the fd, the original is no longer needed
        // prevents file descriptor leaks

        // Input redirection
        if (infile != NULL) {
            // Opens the file for reading only
            int fd = open(infile, O_RDONLY);
            // If opening fails, prints error and exits
            if (fd < 0) { 
                perror ("open infile"); 
                exit(EXIT_FAILURE);
            }
            // Use dup2() to make the file descriptor replace standard input (fd 0)
            dup2(fd, STDIN_FILENO);
            // Now, STDIN_FILENO (0) -> input file (instead of terminal)
            close(fd);
        }

        // Output redirection
        if (outfile != NULL) {
            // Opens the file with Write only, Create if doesn't exist, Truncate (clear) if exists
            // File permission 0644 => rw-r--r--
            int fd = open(outfile, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd < 0) {
                perror("open outfile");
                exit(EXIT_FAILURE);
            }
            // Use dup2() to make the file descriptor replace standard output (fd 1)
            dup2(fd, STDOUT_FILENO);
            // Now, STDOUT_FILENO (1) -> output file (instead of terminal)
            close(fd);
        }

        // Note:
        // No need to worry about replacing the file descriptors back to default
        // After execvp() is called, the child process is replaced anyway, so the redirection only affects the child
        // The parent still has its original STDIN/STDOUT

        // execvp(const char *file, char *const argv[])
        // Execute the program
        if (execv(args[0], args) == -1) {
            // If successful, never returns, process is replaced
            fprintf(stderr, "dragonshell: Command not found\n");
            exit(EXIT_FAILURE);
        }
    
    } else if (pid > 0) { // Parent process (my shell)

        // Put child in its own process group
        setpgid(pid, pid);
        
        // Foreground Job (ie. background = 0)
        if (!background) {
            // Give terminal control to child
            tcsetpgrp(STDIN_FILENO, pid);

            int freed_cmd_str = 0;
            
            // // Wait for child to finish or stop
            // waitpid(pid, &status, WUNTRACED);
            // // Returns terminal control to shell
            // tcsetpgrp(STDIN_FILENO, getpgrp());
            // // Update child in process table
            // // update_job_state(pid, status);

            do {
                waitpid(pid, &status, WUNTRACED); // wait until child stops or terminates
                if (WIFSTOPPED(status)) {
                    // Child has been stopped (not terminated)
                    // update_job_state(pid, 'T'); // Update state to 'T' for stopped
                    // The above design gave me ghost jobs when I ran a foreground job that exited with non-zero status
                    // Add child to process table
                    add_job(pid, 'T', cmd_str);
                    printf("\n[%d]+ Stopped %s\n", job_id_for(pid), cmd_str);
                    free(cmd_str);
                    freed_cmd_str = 1;
                    break;
                }
            } while (!WIFEXITED(status) && !WIFSIGNALED(status));
            
            if (!freed_cmd_str) {free(cmd_str);}

            // If the child exited with non-zero status, we don't need to do add it to the job list
            if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
                remove_job(pid);
            }
            
            tcsetpgrp(STDIN_FILENO, getpgrp()); // Return terminal control to shell

        } else {
            // Background job - return to prompt
            // Add child to process table
            add_job(pid, 'R', cmd_str); // 'R' for running
            free(cmd_str);
            // No terminal control transfer, no waiting, prints background job info
            printf("PID %d is sent to background\n", pid);
        }
    } else {
        perror("fork");
    }
    return 1; // to keep the shell running
}

// Function to execute shell command
// =================================
int dragon_execute(char **args, char *line) {
    if (args[0] == NULL) {
        // An empty command was entered
        return 1;
    }

    // Save the original args for job table
    char *cmd_str = strdup(line);

    // Remove double quotes from all args
    for (int j = 0; args[j] != NULL; j++) {
        remove_quotes(args[j]);
    }

    // No builtins for pipe
    for (int i = 0; args[i] != NULL; i++) {
        if (strcmp(args[i],"|") == 0) {
            // Single pipe detected
            args[i] = NULL; // Terminate the first command

            char **cmd1 = args;       // First command (everything before |)
            char **cmd2 = &args[i+1]; // Second command (everything after |)

            if (cmd1[0] == NULL || cmd2[0] == NULL) {
            fprintf(stderr, "dragonshell: invalid pipe syntax\n");
            return 1;
            }

            int pipefd[2];
            // Create a pipe - pipefd[0] for reading, pipefd[1] for writing
            if (pipe(pipefd) == -1) {
                perror("pipe");
                return 1;
            }

            // First Child Process (left side of pipe)
            pid_t pid1 = fork();
            if (pid1 == 0) {
                // Redirect stdout to pipe write end
                // Command output goes into the pipe instead of terminal
                dup2(pipefd[1], STDOUT_FILENO);
                close(pipefd[0]); // close unused read end
                close(pipefd[1]); // close original write end
                if (execv(cmd1[0], cmd1) == -1) {
                    perror("dragonshell: exec error");
                    exit(EXIT_FAILURE);
                }
            }

            // Second Child Process (right side of pipe)
            pid_t pid2 = fork();
            if (pid2 == 0) {
                // Redirect stdin to pipe read end
                // Command input comes from the pipe instead of terminal
                dup2(pipefd[0], STDIN_FILENO); // stdin <- pipe read
                close(pipefd[1]); // close unused write end
                close(pipefd[0]);
                if (execv(cmd2[0], cmd2) == -1) {
                    perror("dragonshell: exec error");
                    exit(EXIT_FAILURE);
                }
            }

            // Parent closes both ends of the pipe (childeren have their own copies)
            // Waits for both children to finish
            close(pipefd[0]);
            close(pipefd[1]);
            int status;
            waitpid(pid1, &status, 0);
            waitpid(pid2, &status, 0);
            free(cmd_str);
            return 1; // to keep the shell running
        }
    }

    // Check if the command (arg[0]) is a builtin command
    for (int i = 0; i < num_builtins(); i++) {
        if (strcmp(args[0], builtin_str[i]) == 0) {
            // Call the corresponding function by derefencing fn pointer
            int ret = (*builtin_func[i])(args);
            free(cmd_str); // Free the duplicated command string
            return ret;    // Return the status from the builtin function
        }
    }

    // Things to accomplish:
    // 1. Detect '&' to marks a background, remove token from args
    // 2. Detect '|' - split into multiple command arrays
    // 3. Detect '<' / '>' to setup redirection
    // 4. Launch Childeren
    // 5. Parent:
    //      If foreground, wait for last child
    //      If background, add last child PID to jobs table

    // Parse for <,>,&
    // Pass parameters to dragon_launch()
    // Modify dragon_launch() to handle redir

    // External command: parse I/O redirection and background
    int background = 0;
    char *infile = NULL;
    char *outfile = NULL;

    // Detect background (&) ; Sets background = 1 if detected
    int last = 0;
    while (args[last] != NULL) last++;
    if (last > 0 && strcmp(args[last-1], "&") == 0) {
        background = 1;
        free( args[last-1] ); // Free the "&" token
        args[last-1] = NULL;  // Remove "&" from args
    }

    // Detect I/O redirection ;
    for (int i = 0; args[i] != NULL; i++) {
        if (strcmp(args[i], "<") == 0 && args[i+1] != NULL) {
            infile = args[i+1];
            free(args[i]);     // free "<"
            args[i] = NULL;    // mark as freed
            // free(args[i+1]);// free filename
            args[i+1] = NULL;  // mark as freed
            i++;                // skip filename
        } else if (strcmp(args[i], ">") == 0 && args[i+1] != NULL) {
            outfile = args[i+1];
            free(args[i]);     // free ">"
            args[i] = NULL;    // mark as freed
            // free(args[i+1]);// free filename
            args[i+1] = NULL;  // mark as freed
            i++;
        }
    }

    // If not a builtin command, launch it as a program
    int status = dragon_launch(args, background, infile, outfile, cmd_str);
    return status;
}

// Function to read a line of input from stdin
// ===========================================
char *dragon_readline(void) {
    static char buffer[LINE_LENGTH]; // fixed-size buffer
    int position = 0;
    int c;

    while (1) {
        c = getchar();

        if (c == EOF) {
            // Exit shell
            exit(EXIT_SUCCESS);
        } else if (c == '\n') {
            buffer[position] = '\0'; // Null terminate my string
            return buffer;
        } else {
            // Line is too long
            if (position >= LINE_LENGTH - 1) {
                buffer[position] = '\0';
                fprintf(stderr, "dragonshell: input line too long\n");
                return buffer;
            }
            // Current value of position is used for indexing, then incremented
            buffer[position++] = (char) c;
        }
    }
}

// Function to split a line into tokens (arguments)
// ================================================
void remove_quotes(char *str) {
    int len = strlen(str);
    if (len >= 2 && ((str[0] == '"' && str[len - 1] == '"'))) {
        memmove(str, str + 1, len - 2); // Shift string left by 1
        str[len - 2] = '\0';            // Null terminate the new string
    }
}

char **tokenize(char *line) {
    // Array of string pointers
    static char *args[MAX_ARGS + 1]; // +1 accounting for Null Terminator
    int arg_count = 0;
    
    // Clear args
    for (int k = 0; k < MAX_ARGS + 1; k++) {
        args[k] = NULL;
    }
    // line is a null-terminated array of chars; line++ => next char in array
    while (*line != '\0' && arg_count < MAX_ARGS) {
        // Skip leading whitespaces
        while (isspace((unsigned char) *line)) {
            line++;
        }
        // End when null pointer reached
        if (*line == '\0') {
            break;
        }
        // Handle special single-char tokens: > < | &
        if (*line == '>' || *line == '<' || *line == '|' || *line == '&') {
            args[arg_count] = malloc(2); // Space for char + '\0'
            if (!args[arg_count]) {
                fprintf(stderr,"dragonshell: allocation error\n");
                exit(EXIT_FAILURE);
            }
            args[arg_count][0] = *line;
            args[arg_count][1] = '\0';
            arg_count++;
            line++; // advance past operator
        } else {
            // Parse a normal word, handling quotes
            args[arg_count] = malloc(MAX_LENGTH + 1);
            if (!args[arg_count]) {
                fprintf(stderr,"dragonshell: allocation error\n");
                exit(EXIT_FAILURE);
            }

            int len = 0;

            if (*line == '"') {
                // Token starts with a quote
                char quote = *line;  // remember " or '
                line++;              // skip opening quote

                while (*line != '\0' && *line != quote) {
                    if (len < MAX_LENGTH) {
                        args[arg_count][len++] = *line;
                    }
                    line++;
                }

                if (*line == quote) line++; // skip closing quote
            } else {
                // Normal word (no quotes)
                while (*line != '\0' && !isspace((unsigned char)*line) &&
                    *line != '>'  && *line != '<' &&
                    *line != '|'  && *line != '&') {
                    if (len < MAX_LENGTH) {
                        args[arg_count][len++] = *line;
                    }
                    line++;
                }
            }

            args[arg_count][len] = '\0';
            arg_count++;
        }
    }
    args[arg_count] = NULL;
    return args; // Returns an array of pointer to string tokens terminated by NULL
}

// Main loop of the shell
// ======================
void dragon_loop(void) {
    char *line;    // Pointer to hold input line
    char **args;   // Pointer to array of argument strings
    int status;    // Status of last command executed
    printf("\nWelcome to Dragon Shell!\n\n");

    do {
        // Start of each iteration, check if flag is set
        if (sigchld_flag) { reap_childeren(); sigchld_flag = 0;}
        printf("dragonshell > ");       // Print prompt
        line = dragon_readline();       // Read a line of input
        args = tokenize(line);          // Split the line into args
        status = dragon_execute(args,line);  // Execute the command

        // Free tokens allocated in tokenize()
        for (int i = 0; args[i] != NULL; i++) {
            free(args[i]);
        }
    } while (status); // Continue until status is 0 (exit command)
}

int main(int argc, char **argv) {
    // Setting up signal behaviour for shell
    setup_shell_signals();
    // Run command loop.
    dragon_loop();
    // Perform any shutdown/cleanup.
    return EXIT_SUCCESS;
}