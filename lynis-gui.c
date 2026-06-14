/*
 * lynis-gui - a friendly GTK3 front-end for Lynis
 *
 * Runs a Lynis system audit and shows the scan live, line by line, with colors:
 *   green  = OK / DONE / ENABLED / FOUND / HARDENED  (good)
 *   amber  = WARNING / WEAK / SUGGESTION / DISABLED   (review)
 *   red    = DANGER / a real WARNING                  (act now)
 *   cyan   = section headers ("[+] ...")
 *
 * Lynis needs root to inspect the system, so the audit is launched through
 * pkexec unless the program is already running as root.
 *
 * Copyright (c) 2026. Released under the MIT license.
 */

#include <gtk/gtk.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#define LYNIS_PATH "/usr/sbin/lynis"

typedef struct {
    GtkWidget    *window;
    GtkWidget    *textview;
    GtkTextBuffer *buffer;
    GtkWidget    *scan_btn;
    GtkWidget    *stop_btn;
    GtkWidget    *clear_btn;
    GtkWidget    *pentest_check;
    GtkWidget    *spinner;
    GtkWidget    *statusbar;
    guint         status_ctx;

    /* running scan state */
    GPid          pid;
    GIOChannel   *out_chan;
    GIOChannel   *err_chan;
    guint         out_watch;
    guint         err_watch;
    guint         child_watch;
    guint         kill_timer;    /* TERM->KILL escalation timeout */
    gboolean      running;
    gboolean      via_pkexec;    /* child runs as root through pkexec */

    /* live tallies */
    int warnings;
    int suggestions;
    int hardening_index;   /* -1 until parsed from the summary */
} App;

/* ---- helpers ---------------------------------------------------------- */

/* Strip ANSI/CSI escape sequences in place. Lynis emits cursor-movement
 * codes (e.g. ESC[41C) to right-align its "[ STATUS ]" markers even under
 * --no-colors, which would otherwise show up as garbage in the text view. */
static void strip_ansi(char *s)
{
    char *w = s;
    for (char *r = s; *r; ) {
        if (*r == '\033') {              /* ESC */
            r++;
            if (*r == '[') {             /* CSI: ESC [ params final */
                r++;
                while (*r && (*r < '@' || *r > '~')) r++; /* params/interm */
                if (*r) r++;             /* consume final byte */
            } else {
                while (*r && *r != '\033') r++; /* other ESC seq: skip */
            }
            continue;
        }
        *w++ = *r++;
    }
    *w = '\0';
}

static gboolean str_icontains(const char *hay, const char *needle)
{
    if (!hay || !needle) return FALSE;
    size_t nlen = strlen(needle);
    for (const char *p = hay; *p; p++) {
        if (g_ascii_strncasecmp(p, needle, nlen) == 0)
            return TRUE;
    }
    return FALSE;
}

/* Extract the LAST bracketed status token of a line, e.g. "[ WARNING ]" ->
 * "WARNING". Returns a newly-allocated, trimmed, upper-cased string or NULL. */
static char *extract_status(const char *line)
{
    const char *open = NULL, *close = NULL;
    for (const char *p = line; *p; p++) {
        if (*p == '[') open = p;
        else if (*p == ']' && open && p > open) close = p;
    }
    if (!open || !close || close < open) return NULL;

    /* token between the brackets, trimmed */
    char *inner = g_strndup(open + 1, close - open - 1);
    char *trimmed = g_strdup(g_strstrip(inner));
    g_free(inner);

    if (trimmed[0] == '\0') { g_free(trimmed); return NULL; }
    /* reject things that aren't simple status words (paths, "GRUB2", etc.
     * are fine too — we only care that it's short and printable) */
    for (char *q = trimmed; *q; q++) *q = g_ascii_toupper(*q);
    return trimmed;
}

/* Decide which color tag a line of Lynis output deserves. */
static const char *classify_line(const char *line)
{
    /* section headers: "[+] Boot and services" */
    if (g_str_has_prefix(line, "[+]"))
        return "header";

    /* "[X]" suggestion / warning markers in the summary block */
    if (g_str_has_prefix(line, "  [!]") || g_str_has_prefix(line, "[!]"))
        return "warn";

    char *st = extract_status(line);
    if (st) {
        const char *tag = NULL;
        if (strcmp(st, "WARNING") == 0 || strcmp(st, "DANGER") == 0)
            tag = "infected";
        else if (strcmp(st, "WEAK") == 0 || strcmp(st, "SUGGESTION") == 0 ||
                 strcmp(st, "DISABLED") == 0 || strcmp(st, "NOT FOUND") == 0 ||
                 strcmp(st, "UNSAFE") == 0 || strcmp(st, "EXPOSED") == 0)
            tag = "warn";
        else if (strcmp(st, "OK") == 0 || strcmp(st, "DONE") == 0 ||
                 strcmp(st, "ENABLED") == 0 || strcmp(st, "FOUND") == 0 ||
                 strcmp(st, "HARDENED") == 0 || strcmp(st, "YES") == 0 ||
                 strcmp(st, "PASSED") == 0 || strcmp(st, "ACTIVE") == 0 ||
                 strcmp(st, "PROTECTED") == 0)
            tag = "ok";
        g_free(st);
        if (tag) return tag;
    }

    if (str_icontains(line, "Hardening index"))
        return "header";

    /* indented "Result:"/"Suggestion:" detail lines */
    if (g_str_has_prefix(line, "        ") || g_str_has_prefix(line, "      - "))
        return "info";

    return NULL; /* plain text */
}

static void append_line(App *app, const char *line, const char *forced_tag)
{
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(app->buffer, &end);

    const char *tag = forced_tag ? forced_tag : classify_line(line);

    if (tag) {
        if (strcmp(tag, "infected") == 0) app->warnings++;
        else if (strcmp(tag, "warn") == 0) {
            /* SUGGESTION-tagged lines count as suggestions, not warnings */
            if (str_icontains(line, "SUGGESTION"))
                app->suggestions++;
            else
                app->warnings++;
        }
        gtk_text_buffer_insert_with_tags_by_name(app->buffer, &end,
                                                 line, -1, tag, NULL);
    } else {
        gtk_text_buffer_insert(app->buffer, &end, line, -1);
    }
    gtk_text_buffer_insert(app->buffer, &end, "\n", -1);

    /* keep the view scrolled to the bottom */
    GtkTextMark *mark = gtk_text_buffer_get_insert(app->buffer);
    gtk_text_view_scroll_mark_onscreen(GTK_TEXT_VIEW(app->textview), mark);
}

static void update_status(App *app)
{
    char msg[256];
    if (app->running)
        g_snprintf(msg, sizeof msg,
                   "Auditing…   warnings: %d   suggestions: %d",
                   app->warnings, app->suggestions);
    else if (app->hardening_index >= 0)
        g_snprintf(msg, sizeof msg,
                   "Finished — hardening index %d/100   (%d warning(s), %d suggestion(s))",
                   app->hardening_index, app->warnings, app->suggestions);
    else if (app->warnings > 0 || app->suggestions > 0)
        g_snprintf(msg, sizeof msg,
                   "Finished — %d warning(s), %d suggestion(s) to review.",
                   app->warnings, app->suggestions);
    else
        g_snprintf(msg, sizeof msg, "Ready.");

    gtk_statusbar_pop(GTK_STATUSBAR(app->statusbar), app->status_ctx);
    gtk_statusbar_push(GTK_STATUSBAR(app->statusbar), app->status_ctx, msg);
}

/* Pull the hardening index out of a summary line like
 * "  Hardening index : 67 [############        ]". */
static void maybe_capture_index(App *app, const char *line)
{
    if (!str_icontains(line, "Hardening index")) return;
    const char *p = strchr(line, ':');
    if (!p) return;
    p++;
    while (*p && !g_ascii_isdigit(*p)) p++;
    if (*p) app->hardening_index = atoi(p);
}

/* ---- scan lifecycle --------------------------------------------------- */

/* Runs in the forked child before exec: start a new process group so the
 * whole Lynis process tree (it spawns many child test processes) can be
 * signalled at once via kill(-pgid, ...). */
static void child_setup(gpointer data)
{
    (void)data;
    setpgid(0, 0);
}

/* Send a signal to the child's entire process group. When we launched Lynis
 * through pkexec it runs as root, so a non-root GUI can't signal it directly
 * (EPERM) — in that case we re-elevate with pkexec to deliver the signal. */
static void signal_scan_group(App *app, int sig)
{
    if (!app->pid) return;

    if (!app->via_pkexec) {
        kill(-(pid_t)app->pid, sig);   /* negative pid -> whole group */
        return;
    }

    char signum[8], target[32];
    g_snprintf(signum, sizeof signum, "-%d", sig);
    g_snprintf(target, sizeof target, "-%d", (int)app->pid); /* -pgid */
    /* The "--" is required so kill(1) treats the negative pgid as a target
     * and not as a bundle of options. */
    char *argv[] = { "pkexec", "kill", signum, "--", target, NULL };
    g_spawn_async(NULL, argv, NULL, G_SPAWN_SEARCH_PATH,
                  NULL, NULL, NULL, NULL);
}

/* If the polite SIGTERM didn't end the scan, escalate to SIGKILL. */
static gboolean force_kill_cb(gpointer data)
{
    App *app = data;
    app->kill_timer = 0;
    if (app->running && app->pid) {
        signal_scan_group(app, SIGKILL);
        append_line(app, "Forcing the audit to stop (SIGKILL).", "warn");
    }
    return G_SOURCE_REMOVE;
}

static void set_running_ui(App *app, gboolean running)
{
    app->running = running;
    gtk_widget_set_sensitive(app->scan_btn, !running);
    gtk_widget_set_sensitive(app->stop_btn, running);
    gtk_widget_set_sensitive(app->pentest_check, !running);
    if (running) {
        gtk_spinner_start(GTK_SPINNER(app->spinner));
        gtk_widget_show(app->spinner);
    } else {
        gtk_spinner_stop(GTK_SPINNER(app->spinner));
        gtk_widget_hide(app->spinner);
    }
    update_status(app);
}

static gboolean on_io(GIOChannel *src, GIOCondition cond, gpointer data)
{
    App *app = data;

    /* Forget the watch id when the source is about to be auto-removed,
     * so cleanup_scan() doesn't try to remove it a second time. */
    guint *watch_id = (src == app->err_chan) ? &app->err_watch
                                             : &app->out_watch;

    if (cond & (G_IO_HUP | G_IO_ERR)) {
        *watch_id = 0;
        return FALSE; /* remove watch */
    }

    char *line = NULL;
    gsize len = 0;
    GError *err = NULL;
    GIOStatus st = g_io_channel_read_line(src, &line, &len, NULL, &err);

    if (st == G_IO_STATUS_NORMAL && line) {
        strip_ansi(line); /* remove cursor-movement escapes Lynis emits */
        g_strchomp(line); /* strip trailing newline */
        const char *forced = (src == app->err_chan) ? "warn" : NULL;
        maybe_capture_index(app, line);
        append_line(app, line, forced);
        update_status(app);
        g_free(line);
        return TRUE;
    }
    if (line) g_free(line);
    if (err) g_error_free(err);
    if (st == G_IO_STATUS_AGAIN)
        return TRUE;
    *watch_id = 0;
    return FALSE; /* EOF -> remove */
}

static void cleanup_scan(App *app)
{
    if (app->kill_timer) { g_source_remove(app->kill_timer); app->kill_timer = 0; }
    if (app->out_watch) { g_source_remove(app->out_watch); app->out_watch = 0; }
    if (app->err_watch) { g_source_remove(app->err_watch); app->err_watch = 0; }
    if (app->out_chan)  { g_io_channel_unref(app->out_chan); app->out_chan = NULL; }
    if (app->err_chan)  { g_io_channel_unref(app->err_chan); app->err_chan = NULL; }
    if (app->pid)       { g_spawn_close_pid(app->pid); app->pid = 0; }
}

static void on_child_exit(GPid pid, gint status, gpointer data)
{
    (void)pid; (void)status;
    App *app = data;
    app->child_watch = 0;

    GtkTextIter end;
    gtk_text_buffer_get_end_iter(app->buffer, &end);
    gtk_text_buffer_insert(app->buffer, &end, "\n", -1);

    char summary[160];
    if (app->hardening_index >= 0)
        g_snprintf(summary, sizeof summary,
                   "=== Audit complete: hardening index %d/100 — "
                   "%d warning(s), %d suggestion(s) ===",
                   app->hardening_index, app->warnings, app->suggestions);
    else
        g_snprintf(summary, sizeof summary,
                   "=== Audit complete: %d warning(s), %d suggestion(s) ===",
                   app->warnings, app->suggestions);
    append_line(app, summary, app->warnings ? "warn" : "ok");

    append_line(app,
        "  \xE2\x84\xB9 Full log: /var/log/lynis.log   "
        "Report data: /var/log/lynis-report.dat", "info");

    cleanup_scan(app);
    set_running_ui(app, FALSE);
}

static void start_scan(App *app)
{
    if (app->running) return;

    app->warnings = 0;
    app->suggestions = 0;
    app->hardening_index = -1;

    gboolean pentest = gtk_toggle_button_get_active(
        GTK_TOGGLE_BUTTON(app->pentest_check));

    /* Build argv. Run through pkexec when we are not root. */
    GPtrArray *argv = g_ptr_array_new();
    gboolean need_priv = (geteuid() != 0);
    app->via_pkexec = need_priv;
    if (need_priv)
        g_ptr_array_add(argv, "pkexec");
    g_ptr_array_add(argv, LYNIS_PATH);
    g_ptr_array_add(argv, "audit");
    g_ptr_array_add(argv, "system");
    g_ptr_array_add(argv, "--quick");       /* don't pause for keypresses */
    g_ptr_array_add(argv, "--no-colors");   /* we apply our own colors */
    if (pentest)
        g_ptr_array_add(argv, "--pentest"); /* non-privileged pentest scope */
    g_ptr_array_add(argv, NULL);

    gint out_fd = -1, err_fd = -1;
    GError *err = NULL;
    gboolean ok = g_spawn_async_with_pipes(
        NULL, (char **)argv->pdata, NULL,
        G_SPAWN_DO_NOT_REAP_CHILD | G_SPAWN_SEARCH_PATH,
        child_setup, NULL, &app->pid,
        NULL, &out_fd, &err_fd, &err);
    g_ptr_array_free(argv, TRUE);

    if (!ok) {
        char buf[512];
        g_snprintf(buf, sizeof buf, "Failed to launch Lynis: %s",
                   err ? err->message : "unknown error");
        append_line(app, buf, "infected");
        if (err) g_error_free(err);
        return;
    }

    char hdr[256];
    g_snprintf(hdr, sizeof hdr, "Starting Lynis system audit%s …",
               need_priv ? " (asking for administrator password)" : "");
    append_line(app, hdr, "header");

    app->out_chan = g_io_channel_unix_new(out_fd);
    app->err_chan = g_io_channel_unix_new(err_fd);
    g_io_channel_set_flags(app->out_chan, G_IO_FLAG_NONBLOCK, NULL);
    g_io_channel_set_flags(app->err_chan, G_IO_FLAG_NONBLOCK, NULL);
    g_io_channel_set_close_on_unref(app->out_chan, TRUE);
    g_io_channel_set_close_on_unref(app->err_chan, TRUE);

    app->out_watch = g_io_add_watch(app->out_chan,
                                    G_IO_IN | G_IO_HUP | G_IO_ERR, on_io, app);
    app->err_watch = g_io_add_watch(app->err_chan,
                                    G_IO_IN | G_IO_HUP | G_IO_ERR, on_io, app);
    app->child_watch = g_child_watch_add(app->pid, on_child_exit, app);

    set_running_ui(app, TRUE);
}

static void stop_scan(App *app)
{
    if (!app->running || !app->pid) return;

    /* Politely signal the whole Lynis process group, then escalate to
     * SIGKILL after a grace period if it hasn't exited yet. */
    signal_scan_group(app, SIGTERM);
    append_line(app, "Stopping the audit…", "warn");

    if (app->kill_timer) g_source_remove(app->kill_timer);
    app->kill_timer = g_timeout_add_seconds(3, force_kill_cb, app);

    /* Don't wait for a second click — disable Stop right away. */
    gtk_widget_set_sensitive(app->stop_btn, FALSE);
}

/* ---- callbacks -------------------------------------------------------- */

static void on_scan_clicked(GtkButton *b, gpointer data) { (void)b; start_scan(data); }
static void on_stop_clicked(GtkButton *b, gpointer data) { (void)b; stop_scan(data); }

static void on_clear_clicked(GtkButton *b, gpointer data)
{
    (void)b;
    App *app = data;
    gtk_text_buffer_set_text(app->buffer, "", -1);
    app->warnings = 0;
    app->suggestions = 0;
    app->hardening_index = -1;
    update_status(app);
}

static void on_save_clicked(GtkButton *b, gpointer data)
{
    (void)b;
    App *app = data;
    GtkWidget *dlg = gtk_file_chooser_dialog_new(
        "Save audit report", GTK_WINDOW(app->window),
        GTK_FILE_CHOOSER_ACTION_SAVE,
        "_Cancel", GTK_RESPONSE_CANCEL,
        "_Save", GTK_RESPONSE_ACCEPT, NULL);
    gtk_file_chooser_set_do_overwrite_confirmation(GTK_FILE_CHOOSER(dlg), TRUE);
    gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(dlg), "lynis-report.txt");

    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_ACCEPT) {
        char *fname = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dlg));
        GtkTextIter s, e;
        gtk_text_buffer_get_bounds(app->buffer, &s, &e);
        char *text = gtk_text_buffer_get_text(app->buffer, &s, &e, FALSE);
        g_file_set_contents(fname, text, -1, NULL);
        g_free(text);
        g_free(fname);
    }
    gtk_widget_destroy(dlg);
}

static gboolean on_delete(GtkWidget *w, GdkEvent *e, gpointer data)
{
    (void)w; (void)e;
    App *app = data;
    if (app->running && app->pid)
        signal_scan_group(app, SIGTERM);
    return FALSE;
}

/* ---- UI construction -------------------------------------------------- */

/* Cyber palette — neon accents on a deep, near-black backdrop. */
#define CY_BG        "#0a0e14"   /* terminal background        */
#define CY_GREEN     "#39ff14"   /* OK — neon green            */
#define CY_CYAN      "#00e5ff"   /* headers — electric cyan    */
#define CY_AMBER     "#ffb000"   /* suggestions — amber        */
#define CY_RED       "#ff2d55"   /* warnings — hot red         */
#define CY_DIM       "#5c6f8a"   /* info / muted               */

static void setup_tags(App *app)
{
    gtk_text_buffer_create_tag(app->buffer, "infected",
        "foreground", "#ffffff", "background", CY_RED,
        "weight", PANGO_WEIGHT_BOLD, NULL);
    gtk_text_buffer_create_tag(app->buffer, "warn",
        "foreground", CY_AMBER, "weight", PANGO_WEIGHT_BOLD, NULL);
    gtk_text_buffer_create_tag(app->buffer, "ok",
        "foreground", CY_GREEN, NULL);
    gtk_text_buffer_create_tag(app->buffer, "header",
        "foreground", CY_CYAN, "weight", PANGO_WEIGHT_BOLD, NULL);
    gtk_text_buffer_create_tag(app->buffer, "info",
        "foreground", CY_DIM, "style", PANGO_STYLE_ITALIC, NULL);
}

/* Install a global dark "cyber" stylesheet for the whole app. */
static void apply_cyber_theme(void)
{
    static const char *css =
        "window, .background {"
        "  background-color: #070a0f;"
        "  color: #c7d3e3;"
        "}"
        "headerbar, headerbar.titlebar {"
        "  background: linear-gradient(180deg, #0e1622, #0a0f18);"
        "  border-bottom: 1px solid #00e5ff;"
        "  box-shadow: 0 1px 8px rgba(0,229,255,0.25);"
        "  min-height: 42px;"
        "  padding: 0 8px;"
        "}"
        "headerbar .title {"
        "  color: #00e5ff;"
        "  font-weight: bold;"
        "  letter-spacing: 2px;"
        "  text-shadow: 0 0 8px rgba(0,229,255,0.6);"
        "}"
        "headerbar .subtitle { color: #5c6f8a; letter-spacing: 1px; }"
        "button {"
        "  background: #0f1622;"
        "  color: #c7d3e3;"
        "  border: 1px solid #1d3147;"
        "  border-radius: 4px;"
        "  padding: 5px 14px;"
        "  font-weight: bold;"
        "  letter-spacing: 1px;"
        "}"
        "button:hover {"
        "  border-color: #00e5ff;"
        "  color: #00e5ff;"
        "  box-shadow: 0 0 8px rgba(0,229,255,0.35);"
        "}"
        "button:active { background: #122033; }"
        "button:disabled { color: #3a475a; border-color: #15202e; }"
        "button#scan {"
        "  border-color: #39ff14; color: #39ff14;"
        "}"
        "button#scan:hover {"
        "  box-shadow: 0 0 10px rgba(57,255,20,0.5);"
        "}"
        "button#stop { border-color: #ff2d55; color: #ff7a90; }"
        "button#stop:hover { box-shadow: 0 0 10px rgba(255,45,85,0.5); }"
        "checkbutton { color: #8aa0bd; }"
        "checkbutton check {"
        "  background: #0f1622; border: 1px solid #1d3147;"
        "}"
        "checkbutton check:checked {"
        "  background: #00e5ff; border-color: #00e5ff;"
        "}"
        "textview, textview text {"
        "  background-color: " CY_BG ";"
        "  color: #aeb9c9;"
        "  caret-color: #39ff14;"
        "}"
        "textview { padding: 6px; }"
        "scrolledwindow {"
        "  border: 1px solid #14202e;"
        "}"
        "statusbar {"
        "  background: #0a0f18;"
        "  color: #5c6f8a;"
        "  border-top: 1px solid #14202e;"
        "  font-size: 90%;"
        "  letter-spacing: 1px;"
        "}"
        "spinner { color: #00e5ff; }";

    GtkCssProvider *prov = gtk_css_provider_new();
    gtk_css_provider_load_from_data(prov, css, -1, NULL);
    gtk_style_context_add_provider_for_screen(
        gdk_screen_get_default(),
        GTK_STYLE_PROVIDER(prov),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(prov);
}

static void build_ui(App *app)
{
    app->window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(app->window),
                         "Lynis — security auditor");
    gtk_window_set_default_size(GTK_WINDOW(app->window), 860, 600);
    gtk_window_set_icon_name(GTK_WINDOW(app->window), "lynis-gui");
    g_signal_connect(app->window, "delete-event", G_CALLBACK(on_delete), app);
    g_signal_connect(app->window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    /* cyber-styled header bar */
    GtkWidget *hbar = gtk_header_bar_new();
    gtk_header_bar_set_show_close_button(GTK_HEADER_BAR(hbar), TRUE);
    gtk_header_bar_set_title(GTK_HEADER_BAR(hbar), "\xE2\x9A\xA1 LYNIS");
    gtk_header_bar_set_subtitle(GTK_HEADER_BAR(hbar),
                                "security auditing console");
    gtk_window_set_titlebar(GTK_WINDOW(app->window), hbar);

    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_container_add(GTK_CONTAINER(app->window), vbox);

    /* toolbar */
    GtkWidget *bar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_container_set_border_width(GTK_CONTAINER(bar), 6);
    gtk_box_pack_start(GTK_BOX(vbox), bar, FALSE, FALSE, 0);

    app->scan_btn = gtk_button_new_with_label("\xE2\x96\xB6 START AUDIT");
    app->stop_btn = gtk_button_new_with_label("\xE2\x96\xA0 STOP");
    app->clear_btn = gtk_button_new_with_label("CLEAR");
    GtkWidget *save_btn = gtk_button_new_with_label("SAVE REPORT");
    gtk_widget_set_sensitive(app->stop_btn, FALSE);

    /* widget names so the stylesheet can give scan/stop their accent colors */
    gtk_widget_set_name(app->scan_btn, "scan");
    gtk_widget_set_name(app->stop_btn, "stop");

    app->spinner = gtk_spinner_new();

    app->pentest_check = gtk_check_button_new_with_label("Pentest mode");
    gtk_widget_set_tooltip_text(app->pentest_check,
        "Run extra penetration-testing checks (--pentest). Focuses on\n"
        "exposure and weak configuration rather than full hardening.");

    gtk_box_pack_start(GTK_BOX(bar), app->scan_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(bar), app->stop_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(bar), app->clear_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(bar), save_btn, FALSE, FALSE, 0);
    gtk_box_pack_end(GTK_BOX(bar), app->spinner, FALSE, FALSE, 6);
    gtk_box_pack_end(GTK_BOX(bar), app->pentest_check, FALSE, FALSE, 6);

    g_signal_connect(app->scan_btn, "clicked", G_CALLBACK(on_scan_clicked), app);
    g_signal_connect(app->stop_btn, "clicked", G_CALLBACK(on_stop_clicked), app);
    g_signal_connect(app->clear_btn, "clicked", G_CALLBACK(on_clear_clicked), app);
    g_signal_connect(save_btn, "clicked", G_CALLBACK(on_save_clicked), app);

    /* text view */
    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
                                   GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_box_pack_start(GTK_BOX(vbox), scroll, TRUE, TRUE, 0);

    app->textview = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(app->textview), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(app->textview), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(app->textview), TRUE);
    gtk_text_view_set_left_margin(GTK_TEXT_VIEW(app->textview), 8);
    gtk_text_view_set_right_margin(GTK_TEXT_VIEW(app->textview), 8);
    gtk_container_add(GTK_CONTAINER(scroll), app->textview);

    app->buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(app->textview));
    setup_tags(app);

    /* legend */
    GtkWidget *legend = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(legend),
        "  <span foreground='" CY_CYAN "'>\xE2\x97\x86 section</span>   "
        "<span foreground='" CY_GREEN "'>\xE2\x97\x8f OK</span>   "
        "<span foreground='" CY_AMBER "'>\xE2\x97\x8f suggestion</span>   "
        "<span background='" CY_RED "' foreground='#ffffff'>\xE2\x97\x8f WARNING</span>");
    gtk_widget_set_halign(legend, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(vbox), legend, FALSE, FALSE, 4);

    /* status bar */
    app->statusbar = gtk_statusbar_new();
    app->status_ctx = gtk_statusbar_get_context_id(
        GTK_STATUSBAR(app->statusbar), "main");
    gtk_box_pack_start(GTK_BOX(vbox), app->statusbar, FALSE, FALSE, 0);

    update_status(app);
}

int main(int argc, char **argv)
{
    gtk_init(&argc, &argv);
    apply_cyber_theme();

    App app;
    memset(&app, 0, sizeof app);
    app.hardening_index = -1;

    build_ui(&app);
    gtk_widget_show_all(app.window);
    gtk_widget_hide(app.spinner); /* hidden until a scan runs */

    gtk_main();
    return 0;
}
