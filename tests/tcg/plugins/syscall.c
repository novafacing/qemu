/*
 * Copyright (C) 2020, Matthias Weckbecker <matthias@weckbecker.name>
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 */
#include <inttypes.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <glib.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

typedef struct {
    int64_t num;
    int64_t calls;
    int64_t errors;
} SyscallStats;

struct SyscallInfo {
    const char *name;
    int64_t write_sysno;
};

const struct SyscallInfo arch_syscall_info[] = {
    { "aarch64", 64 },
    { "aarch64_be", 64 },
    { "alpha", 4 },
    { "arm", 4 },
    { "armeb", 4 },
    { "avr", -1 },
    { "cris", -1 },
    { "hexagon", 64 },
    { "hppa", -1 },
    { "i386", 4 },
    { "loongarch64", -1 },
    { "m68k", 4 },
    { "microblaze", 4 },
    { "microblazeel", 4 },
    { "mips", 1 },
    { "mips64", 1 },
    { "mips64el", 1 },
    { "mipsel", 1 },
    { "mipsn32", 1 },
    { "mipsn32el", 1 },
    { "or1k", -1 },
    { "ppc", 4 },
    { "ppc64", 4 },
    { "ppc64le", 4 },
    { "riscv32", 64 },
    { "riscv64", 64 },
    { "rx", -1 },
    { "s390x", -1 },
    { "sh4", -1 },
    { "sh4eb", -1 },
    { "sparc", 4 },
    { "sparc32plus", 4 },
    { "sparc64", 4 },
    { "tricore", -1 },
    { "x86_64", 1 },
    { "xtensa", 13 },
    { "xtensaeb", 13 },
    { NULL, -1 },
};

static GMutex lock;
static GHashTable *statistics;
static bool do_log_writes;
static int64_t write_sysno = -1;

static SyscallStats *get_or_create_entry(int64_t num)
{
    SyscallStats *entry =
        (SyscallStats *) g_hash_table_lookup(statistics, GINT_TO_POINTER(num));

    if (!entry) {
        entry = g_new0(SyscallStats, 1);
        entry->num = num;
        g_hash_table_insert(statistics, GINT_TO_POINTER(num), (gpointer) entry);
    }

    return entry;
}

static void vcpu_syscall(qemu_plugin_id_t id, unsigned int vcpu_index,
                         int64_t num, uint64_t a1, uint64_t a2,
                         uint64_t a3, uint64_t a4, uint64_t a5,
                         uint64_t a6, uint64_t a7, uint64_t a8)
{
    if (statistics) {
        SyscallStats *entry;
        g_mutex_lock(&lock);
        entry = get_or_create_entry(num);
        entry->calls++;
        g_mutex_unlock(&lock);
    } else {
        g_autofree gchar *out = g_strdup_printf("syscall #%" PRIi64 "\n", num);
        qemu_plugin_outs(out);
    }

    if (do_log_writes && num == write_sysno) {
        GByteArray *data = qemu_plugin_read_memory_vaddr(a2, a3);

        g_autoptr(GString) out = g_string_new("");

        size_t rows = (data->len % 16 == 0)
            ? (data->len / 16)
            : ((data->len / 16) + 1);
        for (size_t row = 0; row < rows; row++) {
            size_t len = (rows != data->len / 16 && row == rows - 1)
                ? (data->len % 16)
                : 16;
            for (size_t i = 0; i < len; i++) {
                g_string_append_printf(out, "%02x ",
                    data->data[(row * 16) + i]);
                if (i != 0 && i % 4 == 0) {
                    g_string_append(out, " ");
                }
            }
            for (size_t i = len; i < 16; i++) {
                g_string_append(out, "   ");
                if (i != 0 && i % 4 == 0) {
                    g_string_append(out, " ");
                }
            }
            g_string_append(out, " | ");
            for (size_t i = 0; i < len; i++) {
                g_string_append_printf(out,
                    (data->data[(row * 16) + i] >= 0x21
                        && data->data[(row * 16) + i] <= 0x7e)
                    ? "%c"
                    : ".", data->data[(row * 16) + i]);
                if (i != 0 && i % 4 == 0) {
                    g_string_append(out, " ");
                }
            }
            g_string_append(out, "\n");
        }


        qemu_plugin_outs(out->str);

        g_byte_array_free(data, TRUE);
    }
}

static void vcpu_syscall_ret(qemu_plugin_id_t id, unsigned int vcpu_idx,
                             int64_t num, int64_t ret)
{
    if (statistics) {
        SyscallStats *entry;

        g_mutex_lock(&lock);
        /* Should always return an existent entry. */
        entry = get_or_create_entry(num);
        if (ret < 0) {
            entry->errors++;
        }
        g_mutex_unlock(&lock);
    } else {
        g_autofree gchar *out = g_strdup_printf(
             "syscall #%" PRIi64 " returned -> %" PRIi64 "\n", num, ret);
        qemu_plugin_outs(out);
    }
}

static void print_entry(gpointer val, gpointer user_data)
{
    SyscallStats *entry = (SyscallStats *) val;
    int64_t syscall_num = entry->num;
    g_autofree gchar *out = g_strdup_printf(
        "%-13" PRIi64 "%-6" PRIi64 " %" PRIi64 "\n",
        syscall_num, entry->calls, entry->errors);
    qemu_plugin_outs(out);
}

static gint comp_func(gconstpointer ea, gconstpointer eb)
{
    SyscallStats *ent_a = (SyscallStats *) ea;
    SyscallStats *ent_b = (SyscallStats *) eb;

    return ent_a->calls > ent_b->calls ? -1 : 1;
}

/* ************************************************************************* */
static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    if (!statistics) {
        return;
    }

    g_mutex_lock(&lock);
    GList *entries = g_hash_table_get_values(statistics);
    entries = g_list_sort(entries, comp_func);
    qemu_plugin_outs("syscall no.  calls  errors\n");

    g_list_foreach(entries, print_entry, NULL);

    g_list_free(entries);
    g_hash_table_destroy(statistics);
    g_mutex_unlock(&lock);
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    bool do_print = false;

    for (int i = 0; i < argc; i++) {
        char *opt = argv[i];
        g_auto(GStrv) tokens = g_strsplit(opt, "=", 2);

        if (g_strcmp0(tokens[0], "print") == 0) {
            if (!qemu_plugin_bool_parse(tokens[0], tokens[1], &do_print)) {
                fprintf(stderr, "boolean argument parsing failed: %s\n", opt);
            }
        } else if (g_strcmp0(tokens[0], "log_writes") == 0) {
            if (!qemu_plugin_bool_parse(tokens[0], tokens[1], &do_log_writes)) {
                fprintf(stderr, "boolean argument parsing failed: %s\n", opt);
            }
        } else {
            fprintf(stderr, "unsupported argument: %s\n", argv[i]);
            return -1;
        }
    }

    if (!do_print) {
        statistics = g_hash_table_new_full(NULL, g_direct_equal, NULL, g_free);
    }

    if (do_log_writes) {
        for (const struct SyscallInfo *syscall_info = arch_syscall_info;
            syscall_info->name != NULL; syscall_info++) {

            if (g_strcmp0(syscall_info->name, info->target_name) == 0) {
                write_sysno = syscall_info->write_sysno;
                break;
            }
        }

        if (write_sysno == -1) {
            fprintf(stderr, "write syscall number not found\n");
            return -1;
        }
    }

    qemu_plugin_register_vcpu_syscall_cb(id, vcpu_syscall);
    qemu_plugin_register_vcpu_syscall_ret_cb(id, vcpu_syscall_ret);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}
