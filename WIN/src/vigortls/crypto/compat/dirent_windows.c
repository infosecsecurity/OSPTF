/*
 * Copyright (c) 2015, Kurt Cancemi (kurt@x64architecture.com)
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdlib.h>
#include <malloc.h>
#include <dirent.h>

DIR *opendir(const char *name)
{
    char *path;
    HANDLE h;
    WIN32_FIND_DATAA *fd;
    DIR *dir;
    int namlen;

    if (name == NULL) {
        return NULL;
    }

    if ((namlen = strlen(name)) == -1) {
        return NULL;
    }

    if (name[namlen - 1] == '\\' || name[namlen - 1] == '/') {
        path = _alloca(namlen + 2);
        strcpy_s(path, namlen + 2, name);
        path[namlen] = '*';
        path[namlen + 1] = '\0';
    } else {
        path = _alloca(namlen + 3);
        strcpy_s(path, namlen + 3, name);

        path[namlen] = (strchr(name, '/') != NULL) ? '/' : '\\';
        path[namlen + 1] = '*';
        path[namlen + 2] = '\0';
    }

    if ((fd = malloc(sizeof(WIN32_FIND_DATA))) == NULL) {
        return NULL;
    }

    if ((h = FindFirstFileA(path, fd)) == INVALID_HANDLE_VALUE) {
        free(fd);
        return NULL;
    }

    if ((dir = malloc(sizeof(DIR))) == NULL) {
        FindClose(h);
        free(fd);
        return NULL;
    }

    dir->h = h;
    dir->fd = fd;
    dir->has_next = TRUE;

    return dir;
}

struct dirent *readdir(DIR *dir)
{
    char *cFileName;
    char *d_name;

    if (dir == NULL) {
        return NULL;
    }

    if (dir->fd == NULL) {
        return NULL;
    }

    if (!dir->has_next) {
        return NULL;
    }

    cFileName = dir->fd->cFileName;
    d_name = dir->entry.d_name;
    strcpy_s(d_name, _MAX_PATH, cFileName);
    dir->has_next = FindNextFileA(dir->h, dir->fd);

    return &dir->entry;
}

int closedir(DIR *dir)
{
    if (dir == NULL) {
        return -1;
    }

    if (dir->h && dir->h != INVALID_HANDLE_VALUE) {
        FindClose(dir->h);
    }

    if (dir->fd) {
        free(dir->fd);
    }

    free(dir);

    return 0;
}
