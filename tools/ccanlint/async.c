#include "ccanlint.h"
#include "../tools.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <assert.h>
#include <ccan/err/err.h>
#include <ccan/lbalance/lbalance.h>
#include <ccan/tlist/tlist.h>
#include <ccan/time/time.h>

#ifdef _WIN32
# define VC_EXTRALEAN 1
# include <windows.h>
#else
# include <sys/resource.h>
# include <sys/time.h>
# include <sys/wait.h>
# include <unistd.h>
#endif

static struct lbalance *lb;
TLIST_TYPE(command, struct command);
static struct tlist_command pending = TLIST_INIT(pending);
static struct tlist_command running = TLIST_INIT(running);
static unsigned int num_running = 0;
static struct tlist_command done = TLIST_INIT(done);

struct command {
	struct list_node list;
	char *command;
#ifdef _WIN32
	HANDLE hProcess;
#endif
	pid_t pid;
	int output_fd;
	unsigned int time_ms;
	struct lbalance_task *task;
	int status;
	char *output;
	bool done;
	const void *ctx;
};

static void killme(int sig UNNEEDED)
{
	kill(-getpid(), SIGKILL);
}

#ifdef _WIN32
/** vwarn(3) equivalent for Windows API errors. */
static void winvwarn(const char *fmt, va_list ap)
{
	LPWSTR lpMsgBuf;
	DWORD dwLastError;

	dwLastError = GetLastError();

	// TODO: Process name. Worth linking to psapi.lib?
	//       https://stackoverflow.com/a/4570213
	//fprintf(stderr, "%s: ", progname);
	vfprintf(stderr, fmt, ap);
	fputs(": ", stderr);
	FormatMessageW(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
			FORMAT_MESSAGE_FROM_SYSTEM |
			FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dwLastError,
		0,
		(LPWSTR) &lpMsgBuf,
		0,
		NULL);
	fwputws(lpMsgBuf, stderr);
}

/** err(3) equivalent for Windows API errors. */
static void winerr(int eval, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	winvwarn(fmt, ap);
	va_end(ap);

	exit(eval);
}
#endif

static void start_command(struct command *c)
{
#ifdef _WIN32
	HANDLE inpipe[2];
	HANDLE outpipe[2];
	PROCESS_INFORMATION pi;
	SECURITY_ATTRIBUTES sa = { 0 };
	STARTUPINFO si = { 0 };

	sa.nLength = sizeof sa;
	sa.bInheritHandle = TRUE;

	// Mimic /dev/null stdin with a closed pipe
	if (!CreatePipe(&inpipe[0], &inpipe[1], &sa, 0))
		winerr(1, "CreatePipe for stdin failed");
	if (!CloseHandle(inpipe[1]))
		winerr(1, "CloseHandle on stdin pipe failed");

	if (!CreatePipe(&outpipe[0], &outpipe[1], &sa, 0))
		winerr(1, "CreatePipe for stdout failed");
	if (!SetHandleInformation(outpipe[0], HANDLE_FLAG_INHERIT, 0))
		winerr(1, "SetHandleInformation for stdout failed");

	si.cb = sizeof si;
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdInput = inpipe[0];
	si.hStdOutput = outpipe[1];
	si.hStdError = outpipe[1];

	if (!CreateProcessA(
			NULL,
			c->command,
			NULL,
			NULL,
			FALSE,
			0,
			NULL,
			NULL,
			&si,
			&pi)) {
		winerr(1, "CreateProcess failed");
	}
	c->hProcess = pi.hProcess;
	c->pid = pi.dwProcessId;

	if (!CloseHandle(pi.hThread)) {
		winvwarn(1, "CloseHandle child thread");
	}
	if (!CloseHandle(inpipe[0]) || !CloseHandle(outpipe[1])) {
		winerr(1, "CloseHandle child pipes");
	}

	// Note:  Closing file descriptor will close handle.
	// https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/open-osfhandle
	c->output_fd = _open_osfhandle((intptr_t)outpipe[1], _O_RDONLY);

#else
	int p[2];

	if (pipe(p) != 0)
		err(1, "Pipe failed");
	c->pid = fork();
	if (c->pid == -1)
		err(1, "Fork failed");
	if (c->pid == 0) {
		struct itimerval itim;

		if (dup2(p[1], STDOUT_FILENO) != STDOUT_FILENO
		    || dup2(p[1], STDERR_FILENO) != STDERR_FILENO
		    || close(p[0]) != 0
		    || close(STDIN_FILENO) != 0
		    || open("/dev/null", O_RDONLY) != STDIN_FILENO)
			exit(128);

		signal(SIGALRM, killme);
		itim.it_interval.tv_sec = itim.it_interval.tv_usec = 0;
		itim.it_value = timespec_to_timeval(time_from_msec(c->time_ms).ts);
		setitimer(ITIMER_REAL, &itim, NULL);

		c->status = system(c->command);
		if (WIFEXITED(c->status))
			exit(WEXITSTATUS(c->status));
		/* Here's a hint... */
		exit(128 + WTERMSIG(c->status));
	}

	close(p[1]);
	c->output_fd = p[0];
#endif

	if (tools_verbose)
		printf("Running async: %s => %i\n", c->command, c->pid);

	c->task = lbalance_task_new(lb);
}

static void run_more(void)
{
	struct command *c;

	while (num_running < lbalance_target(lb)) {
		c = tlist_top(&pending, list);
		if (!c)
			break;

		fflush(stdout);
		start_command(c);
		tlist_del_from(&pending, c, list);
		tlist_add_tail(&running, c, list);
		num_running++;
	}
}

static void destroy_command(struct command *command)
{
	if (!command->done && command->pid) {
#ifdef _WIN32
		TerminateProcess(command->hProcess, 1);
#else
		kill(-command->pid, SIGKILL);
#endif

		close(command->output_fd);
		num_running--;
	}

	tlist_del(command, list);
}

void run_command_async(const void *ctx, unsigned int time_ms,
		       const char *fmt, ...)
{
	struct command *command;
	va_list ap;

	assert(ctx);

	if (!lb)
		lb = lbalance_new();

	command = tal(ctx, struct command);
	command->ctx = ctx;
	command->time_ms = time_ms;
	command->pid = 0;
	/* We want to track length, so don't use tal_strdup */
	command->output = tal_arrz(command, char, 1);
	va_start(ap, fmt);
	command->command = tal_vfmt(command, fmt, ap);
	va_end(ap);
	tlist_add_tail(&pending, command, list);
	command->done = false;
	tal_add_destructor(command, destroy_command);

	run_more();
}

static void reap_output(void)
{
	fd_set in;
	struct command *c, *next;
	int max_fd = 0;

	FD_ZERO(&in);

	tlist_for_each(&running, c, list) {
		FD_SET(c->output_fd, &in);
		if (c->output_fd > max_fd)
			max_fd = c->output_fd;
	}

	if (select(max_fd+1, &in, NULL, NULL, NULL) < 0)
		err(1, "select failed");

	tlist_for_each_safe(&running, c, next, list) {
		if (FD_ISSET(c->output_fd, &in)) {
			int old_len, len;
			/* This length includes nul terminator! */
			old_len = tal_count(c->output);
			tal_resize(&c->output, old_len + 1024);
			len = read(c->output_fd, c->output + old_len - 1, 1024);
			if (len < 0)
				err(1, "Reading from async command");
			tal_resize(&c->output, old_len + len);
			c->output[old_len + len - 1] = '\0';
			if (len == 0) {
				struct rusage ru;
#ifdef _WIN32
				WaitForSingleObject(c->hProcess, INFINITE);
				GetExitCodeProcess(c->hProcess, &c->status);
				CloseHandle(c->hProcess);
				if (tools_verbose)
					printf("Finished async %i: "
							"exit status %u\n",
					       c->pid,
					       c->status);
#else
				wait4(c->pid, &c->status, 0, &ru);
				if (tools_verbose)
					printf("Finished async %i: %s %u\n",
					       c->pid,
					       WIFEXITED(c->status)
					       ? "exit status"
					       : "killed by signal",
					       WIFEXITED(c->status)
					       ? WEXITSTATUS(c->status)
					       : WTERMSIG(c->status));
#endif
				lbalance_task_free(c->task, &ru);
				c->task = NULL;
				c->done = true;
				close(c->output_fd);
				tlist_del_from(&running, c, list);
				tlist_add_tail(&done, c, list);
				num_running--;
			}
		}
	}
}

void *collect_command(bool *ok, char **output)
{
	struct command *c;
	const void *ctx;

	while ((c = tlist_top(&done, list)) == NULL) {
		if (tlist_empty(&pending) && tlist_empty(&running))
			return NULL;
		reap_output();
		run_more();
	}

#ifdef _WIN32
	*ok = (c->status == 0);
#else
	*ok = (WIFEXITED(c->status) && WEXITSTATUS(c->status) == 0);
#endif
	ctx = c->ctx;
	*output = tal_steal(ctx, c->output);
	tal_free(c);
	return (void *)ctx;
}

/* Compile and link single C file, with object files, async. */
void compile_and_link_async(const void *ctx, unsigned int time_ms,
			    const char *cfile, const char *ccandir,
			    const char *objs, const char *compiler,
			    const char *cflags,
			    const char *libs, const char *outfile)
{
	if (compile_verbose)
		printf("Compiling and linking (async) %s\n", outfile);
	run_command_async(ctx, time_ms,
			  "%s %s -I%s -o %s %s %s %s",
			  compiler, cflags,
			  ccandir, outfile, cfile, objs, libs);
}
