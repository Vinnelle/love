/* love — Infra CLI for vinnel.cloud
 * Build: cc -O3 -o bin/love bin/love.c
 *
 * Fast path: execvp() replaces the process for single-command dispatches
 * (pods, certs, ingress, plan, output) — no fork, no wait, zero overhead.
 * services() forks three sequential children.
 * figlet subprocess removed; static fallback always wins.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define P   "\033[38;5;219m"  /* pink     */
#define LV  "\033[38;5;183m"  /* lavender */
#define DIM "\033[38;5;244m"  /* dim gray — section labels */
#define R   "\033[0m"         /* reset    */
#define B   "\033[1m"         /* bold     */

static const char *KITTY[4] = {
    "  (\\  /)   ",
    "  ( \xE2\x80\xA2\xCF\x89\xE2\x80\xA2)   ",  /* •ω•  */
    "  (\xE3\x81\xA3  \xE3\x81\xA4  ",             /* っ  つ */
    "   \xE3\x81\x97---J  ",                        /* し   */
};

static const char *LOGO[4] = {
    "     _               _      _             _",
    "__ _(_)_ _  _ _  ___| |  __| |___ _  _ __| |",
    "\\ V / | ' \\| ' \\/ -_) |_/ _| / _ \\ || / _` |",
    " \\_/|_|_||_|_||_\\___|_(_)__|_\\___/\\_,_\\__,_|",
};

static char projects_dir[PATH_MAX];

/* resolve repo root from /proc/self/exe — no argv[0] guessing */
static void init(void) {
    char exe[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n < 0) { perror("readlink"); exit(1); }
    exe[n] = '\0';
    char *p = strrchr(exe, '/'); if (p) *p = '\0';  /* strip binary name */
    char *q = strrchr(exe, '/'); if (q) *q = '\0';  /* strip /bin        */
    snprintf(projects_dir, sizeof(projects_dir), "%s/projects", exe);
}

static void logo(void) {
    putchar('\n');
    for (int i = 0; i < 4; i++)
        printf(P "%s" LV "%s" R "\n", KITTY[i], LOGO[i]);
    putchar('\n');
}

static char *project(const char *name) {
    static char path[PATH_MAX];
    if (!strcmp(name, ".")) {
        if (!getcwd(path, sizeof(path))) { perror("getcwd"); exit(1); }
        return path;
    }
    snprintf(path, sizeof(path), "%s/%s", projects_dir, name);
    struct stat st;
    if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) return path;

    fprintf(stderr, "project '%s' not found. available:", name);
    DIR *d = opendir(projects_dir);
    if (d) {
        struct dirent *e;
        while ((e = readdir(d)))
            if (e->d_name[0] != '.') fprintf(stderr, " %s", e->d_name);
        closedir(d);
    }
    fputs("\n", stderr);
    exit(1);
}

/* fork+exec+wait — only used by services (multiple sequential commands) */
static void run(char *args[]) {
    pid_t pid = fork();
    if (pid == 0) { execvp(args[0], args); perror(args[0]); _exit(127); }
    if (pid < 0)  { perror("fork"); exit(1); }
    waitpid(pid, NULL, 0);
}

static void hr(int n) {
    printf(LV);
    for (int i = 0; i < n; i++) fputs("\xe2\x94\x80", stdout);  /* ─ */
    printf(R);
}

static void group(const char *label, const char *cmds[][2], int n) {
    printf(DIM "  %s\n" R, label);
    for (int i = 0; i < n; i++)
        printf("    " P "%-28s" R "%s\n", cmds[i][0], cmds[i][1]);
    putchar('\n');
}

static void usage(void) {
    static const char *tf[][2] = {
        {"plan <project> [tf-args]",   "terraform plan in project dir"},
        {"output <project>",           "terraform output in project dir"},
        {"fmt <project> [tf-args]",    "terraform fmt in project dir"},
    };
    static const char *kc[][2] = {
        {"pods [-n ns]",               "kubectl get pods -A"},
        {"certs",                      "kubectl get certificates -A"},
        {"ingress",                    "kubectl get ingress -A"},
        {"events",                     "kubectl get events -A, sorted"},
        {"logs <pod> [kubectl-args]",  "kubectl logs"},
        {"services",                   "pods + ingress + certs in one shot"},
    };
    static const char *nb[][2] = {
        {"peers",                      "list netbird peers (needs NETBIRD_PAT)"},
    };
    static const char *sh[][2] = {
        {"completion",                 "print bash completion script"},
    };

    logo();
    printf(" \xe2\x95\xad"); hr(38); printf(LV "\xe2\x95\xae" R "\n");
    printf(" \xe2\x94\x82  " B "love" R " \xe2\x80\x94 Infra CLI for vinnel.cloud   " LV "\xe2\x94\x82" R "\n");
    printf(" \xe2\x95\xb0"); hr(38); printf(LV "\xe2\x95\xaf" R "\n\n");

    printf("  " LV "usage:" R " love <command> [args]\n\n");
    group("terraform", tf, 3);
    group("kubectl",   kc, 6);
    group("netbird",   nb, 1);
    group("shell",     sh, 1);
}

int main(int argc, char *argv[]) {
    init();

    if (argc < 2 || !strcmp(argv[1], "-h") ||
        !strcmp(argv[1], "--help") || !strcmp(argv[1], "help")) {
        usage(); return 0;
    }

    const char *cmd = argv[1];
    char **rest = argv + 2;
    int nr = argc - 2;

    /* hidden: used by shell completion to list project dirs */
    if (!strcmp(cmd, "--list-projects")) {
        DIR *d = opendir(projects_dir);
        if (d) {
            struct dirent *e;
            while ((e = readdir(d)))
                if (e->d_name[0] != '.') printf("%s\n", e->d_name);
            closedir(d);
        }
        return 0;
    }

    if (!strcmp(cmd, "completion")) {
        puts(
            "_love_completions() {\n"
            "    local cur cmds\n"
            "    cur=\"${COMP_WORDS[COMP_CWORD]}\"\n"
            "    cmds=\"plan output fmt pods certs ingress events logs services peers help\"\n"
            "    if [ \"$COMP_CWORD\" -eq 1 ]; then\n"
            "        COMPREPLY=($(compgen -W \"$cmds\" -- \"$cur\"))\n"
            "        return\n"
            "    fi\n"
            "    case \"${COMP_WORDS[1]}\" in\n"
            "        plan|output|fmt)\n"
            "            COMPREPLY=($(compgen -W \"$(love --list-projects)\" -- \"$cur\"))\n"
            "            ;;\n"
            "    esac\n"
            "}\n"
            "complete -F _love_completions love"
        );
        return 0;
    }

    /* ── terraform commands ─────────────────────────────────────────── */
    if (!strcmp(cmd, "plan") || !strcmp(cmd, "output") || !strcmp(cmd, "fmt")) {
        if (!nr) { fprintf(stderr, "usage: love %s <project> [tf-args]\n", cmd); return 1; }
        char *proj = project(rest[0]);
        int extra = strcmp(cmd, "output") ? nr - 1 : 0;
        char **args = malloc((5 + extra + 1) * sizeof *args);
        args[0] = "direnv"; args[1] = "exec"; args[2] = proj;
        args[3] = "terraform"; args[4] = (char *)cmd;
        for (int i = 0; i < extra; i++) args[5 + i] = rest[1 + i];
        args[5 + extra] = NULL;
        execvp("direnv", args);  /* replaces process — no fork */
        perror("direnv"); return 127;
    }

    /* ── kubectl single-shot commands (execvp: no fork) ────────────── */
    if (!strcmp(cmd, "pods")) {
        char **args = malloc((4 + nr + 1) * sizeof *args);
        args[0] = "kubectl"; args[1] = "get"; args[2] = "pods"; args[3] = "-A";
        for (int i = 0; i < nr; i++) args[4 + i] = rest[i];
        args[4 + nr] = NULL;
        execvp("kubectl", args);
        perror("kubectl"); return 127;
    }

    if (!strcmp(cmd, "certs")) {
        char *args[] = { "kubectl", "get", "certificates", "-A", NULL };
        execvp("kubectl", args);
        perror("kubectl"); return 127;
    }

    if (!strcmp(cmd, "ingress")) {
        char *args[] = { "kubectl", "get", "ingress", "-A", NULL };
        execvp("kubectl", args);
        perror("kubectl"); return 127;
    }

    if (!strcmp(cmd, "events")) {
        char *args[] = { "kubectl", "get", "events", "-A", "--sort-by=.lastTimestamp", NULL };
        execvp("kubectl", args);
        perror("kubectl"); return 127;
    }

    if (!strcmp(cmd, "logs")) {
        if (!nr) { fprintf(stderr, "usage: love logs <pod> [kubectl-args]\n"); return 1; }
        char **args = malloc((nr + 3) * sizeof *args);
        args[0] = "kubectl"; args[1] = "logs"; args[2] = rest[0];
        for (int i = 1; i < nr; i++) args[2 + i] = rest[i];
        args[nr + 2] = NULL;
        execvp("kubectl", args);
        perror("kubectl"); return 127;
    }

    /* ── netbird: list peers via management API ─────────────────────── */
    if (!strcmp(cmd, "peers")) {
        if (!getenv("NETBIRD_PAT")) { fprintf(stderr, "NETBIRD_PAT not set\n"); return 1; }
        /* token passed via env, not argv — invisible to ps */
        char *args[] = { "sh", "-c",
            "curl -sf -H \"Authorization: Token $NETBIRD_PAT\" "
            "https://proxy.vinnel.cloud/api/peers | "
            "jq -r '([\"NAME\",\"IP\",\"CONNECTED\",\"LAST SEEN\"] | @tsv), "
            "(.[] | [.name, .ip, (.connected|tostring), .last_seen] | @tsv)' "
            "| column -t -s \"$(printf '\\t')\"", NULL };
        execvp("sh", args);
        perror("sh"); return 127;
    }

    /* ── services: three sequential kubectl calls ───────────────────── */
    if (!strcmp(cmd, "services")) {
        static const struct { const char *label, *res; } svc[3] = {
            { "pods",         "pods"         },
            { "ingress",      "ingress"      },
            { "certificates", "certificates" },
        };
        for (int i = 0; i < 3; i++) {
            printf("\n" LV "\xe2\x94\x80\xe2\x94\x80 %s \xe2\x94\x80\xe2\x94\x80" R "\n", svc[i].label);
            fflush(stdout);
            char *args[] = { "kubectl", "get", (char *)svc[i].res, "-A", NULL };
            run(args);
        }
        putchar('\n');
        return 0;
    }

    fprintf(stderr, "unknown command: %s\n", cmd);
    usage();
    return 1;
}
