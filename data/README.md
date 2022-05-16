
### static reachable:
- `strncmp`: strncmp
- `strcpy`: strcpy
- `memcpy`: memcpy

### decision tree
we set the rest decision tree accroding to the source code:
- free

```c
void __libc_free(void *mem) {
    ...
    if (mem == 0)
        return;
    ...
}
```
- fprintf

```c
  if (bytes_requested == 0)
    return 0;
```
- system

```c
int
__libc_system (const char *line)
{
...
  if (line == NULL)
    return __libc_system ("exit 0") == 0;
...
}

```