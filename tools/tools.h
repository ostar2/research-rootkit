#ifndef TOOLS
#define TOOLS

struct NODE
{
    char *s;
    struct NODE *nex;
    struct NODE *pre;
};
char *get_simpified_path(const char* absolute_path);
#endif
