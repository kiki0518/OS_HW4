// multilevelBF.c
#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>

// ---- Configuration ----
#define POOL_SIZE 20000
#define LEVELS 12
#define NODE_POOL_SIZE 1024   // enough nodes for bookkeeping
#define ALIGN 32

// ---- Metadata (exactly 32 bytes) ----
typedef struct metadata {
    size_t size;             // 8 bytes: size of data (excluding header)
    struct metadata *left;   // 8 bytes: left neighbor chunk (NULL if none)
    struct metadata *right;  // 8 bytes: right neighbor chunk (NULL if none)
    unsigned int status;     // 4 bytes: 0=FREE,1=USED
    unsigned int id;         // 4 bytes: debug id
} metadata; // total: 32 bytes

// ---- Node for free lists (kept in a static pool) ----
typedef struct node {
    struct node *next;
    struct node *prev;
    struct metadata *curr; // points to metadata header of chunk
} node;

typedef struct layer {
    node *head;
    node *tail;
} layer;

// ---- Globals ----
static bool first_malloc = true;
static void *chunk_list = NULL; // base of mmap pool
static layer multilevel_list[LEVELS];
static node node_pool[NODE_POOL_SIZE];
static int node_pool_free_stack[NODE_POOL_SIZE];
static int node_pool_top = 0; // stack pointer
static unsigned int global_id = 1;

// ---- Helpers ----
static inline size_t align_size(size_t s) {
    if (s == 0) return 0;
    return (s + (ALIGN - 1)) & ~(ALIGN - 1);
}

static int multilevel_index(size_t size) {
    // choose level i such that size <= (32 << i)
    for (int i = 0; i < LEVELS; ++i) {
        if (size <= ( (size_t)32 << i )) return i;
    }
    return LEVELS - 1;
}

// node pool allocation (no runtime malloc)
static node* node_alloc_from_pool() {
    if (node_pool_top <= 0) return NULL;
    int idx = node_pool_free_stack[--node_pool_top];
    node *n = &node_pool[idx];
    n->next = n->prev = NULL;
    n->curr = NULL;
    return n;
}

static void node_free_to_pool(node *n) {
    if (n == NULL) return;
    int idx = (int)(n - node_pool);
    if (node_pool_top < NODE_POOL_SIZE) {
        node_pool_free_stack[node_pool_top++] = idx;
    }
}

// insert node (with n->curr set) to tail of multilevel_list[level]
static void insert_free_node_at_tail(int level, node *n) {
    if (!n) return;
    layer *lst = &multilevel_list[level];
    n->next = NULL;
    n->prev = lst->tail;
    if (lst->tail) lst->tail->next = n;
    lst->tail = n;
    if (!lst->head) lst->head = n;
}

// remove a node from its list (does not free node)
static void remove_free_node(node *n, int level) {
    if (!n) return;
    layer *lst = &multilevel_list[level];
    if (n->prev) n->prev->next = n->next;
    else lst->head = n->next;
    if (n->next) n->next->prev = n->prev;
    else lst->tail = n->prev;
    n->next = n->prev = NULL;
}

// find the node level for a given node's curr->size
static int node_level_from_node(node *n) {
    if (!n || !n->curr) return -1;
    return multilevel_index(n->curr->size);
}

// find best-fit node starting from level "start"
static node* find_best_fit_node(int start_level) {
    node *best = NULL;
    for (int lvl = start_level; lvl < LEVELS; ++lvl) {
        node *cur = multilevel_list[lvl].head;
        while (cur) {
            if (cur->curr && cur->curr->status == 0) {
                if (!best || cur->curr->size < best->curr->size) {
                    best = cur;
                }
            }
            cur = cur->next;
        }
        if (best && best->curr->size == ((size_t)32 << start_level)) {
            // small optimization: if perfect fit for the starting bin
            break;
        }
    }
    return best;
}

// compute largest free chunk (data size only)
static size_t largest_free_chunk() {
    size_t max = 0;
    for (int lvl = 0; lvl < LEVELS; ++lvl) {
        node *cur = multilevel_list[lvl].head;
        while (cur) {
            if (cur->curr && cur->curr->status == 0) {
                if (cur->curr->size > max) max = cur->curr->size;
            }
            cur = cur->next;
        }
    }
    return max;
}

// given a metadata pointer, add it to appropriate multilevel free list (append tail)
static int add_meta_to_free_list(metadata *m) {
    if (!m) return -1;
    int lvl = multilevel_index(m->size);
    node *n = node_alloc_from_pool();
    if (!n) return -1;
    n->curr = m;
    n->next = n->prev = NULL;
    insert_free_node_at_tail(lvl, n);
    return 0;
}

// remove a metadata from its free list (search node pool to find node)
static int remove_meta_from_free_list(metadata *m) {
    if (!m) return -1;
    int lvl = multilevel_index(m->size);
    node *cur = multilevel_list[lvl].head;
    while (cur) {
        if (cur->curr == m) {
            remove_free_node(cur, lvl);
            node_free_to_pool(cur);
            return 0;
        }
        cur = cur->next;
    }
    // not found
    return -1;
}

// ---- malloc / free implementation ----

void *malloc(size_t size) {
    // first-time init
    if (first_malloc) {
        first_malloc = false;

        // initialize node pool stack
        node_pool_top = 0;
        for (int i = NODE_POOL_SIZE - 1; i >= 0; --i) {
            node_pool_free_stack[node_pool_top++] = i;
        }

        // mmap pool
        chunk_list = mmap(NULL, POOL_SIZE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
        if (chunk_list == MAP_FAILED) {
            chunk_list = NULL;
            return NULL;
        }

        // init multilevel lists
        for (int i = 0; i < LEVELS; ++i) {
            multilevel_list[i].head = multilevel_list[i].tail = NULL;
        }

        // initial metadata at start of pool
        metadata *initial_meta = (metadata *)chunk_list;
        initial_meta->size = POOL_SIZE - sizeof(metadata);
        initial_meta->left = NULL;
        initial_meta->right = NULL;
        initial_meta->status = 0; // FREE
        initial_meta->id = global_id++;

        // add to highest appropriate level
        add_meta_to_free_list(initial_meta);
    }

    // special fake request: size == 0 => print largest free chunk and munmap then return NULL
    if (size == 0) {
        size_t maxfree = largest_free_chunk();
        char buf[128];
        int len = sprintf(buf, "Max Free Chunk Size = %zu\n", maxfree);
        if (len > 0) write(STDOUT_FILENO, buf, (size_t)len);
        if (chunk_list) {
            munmap(chunk_list, POOL_SIZE);
            chunk_list = NULL;
        }
        return NULL;
    }

    // round size to ALIGN
    size_t asize = align_size(size);

    // find best-fit node starting from appropriate level
    int start_lvl = multilevel_index(asize);
    node *best_node = NULL;
    size_t best_size = 0;
    for (int lvl = start_lvl; lvl < LEVELS; ++lvl) {
        node *cur = multilevel_list[lvl].head;
        while (cur) {
            if (cur->curr && cur->curr->status == 0) {
                if (!best_node || cur->curr->size < best_size) {
                    best_node = cur;
                    best_size = cur->curr->size;
                }
            }
            cur = cur->next;
        }
        if (best_node) break; // found best in or above level
    }

    if (!best_node) {
        // no suitable block
        return NULL;
    }

    // allocate from best_node
    metadata *m = best_node->curr;
    int old_lvl = multilevel_index(m->size);
    // remove from free list
    remove_free_meta:
    // remove node corresponding to m
    {
        node *cur = multilevel_list[old_lvl].head;
        while (cur) {
            if (cur->curr == m) {
                remove_free_node(cur, old_lvl);
                node_free_to_pool(cur);
                break;
            }
            cur = cur->next;
        }
    }

    // if exact fit or not enough room to split (need space for new metadata + minimal alignment)
    if (m->size >= asize && (m->size - asize) >= (ssize_t) ( (ssize_t)sizeof(metadata) + (ssize_t)ALIGN) ) {
        // split
        metadata *new_meta = (metadata *)((char*)m + sizeof(metadata) + asize);
        // set up new_meta
        new_meta->size = m->size - asize - sizeof(metadata);
        new_meta->left = m;
        new_meta->right = m->right;
        new_meta->status = 0; // free
        new_meta->id = global_id++;

        // fix neighbor pointers
        if (m->right) {
            m->right->left = new_meta;
        }
        m->right = new_meta;
        // shrink current
        m->size = asize;
        m->status = 1; // used
        m->id = global_id++;

        // add new_meta to free list
        add_meta_to_free_list(new_meta);
    } else {
        // allocate entire chunk (no split)
        m->status = 1; // used
        m->id = global_id++;
        // if there is leftover too small to contain metadata+alignment, we allocate whole chunk
    }

    // return pointer to user data (just after header)
    void *user_ptr = (void *)((char*)m + sizeof(metadata));
    return user_ptr;
}

void free(void *ptr) {
    if (!ptr) return;
    // find metadata header
    metadata *m = (metadata *)((char*)ptr - sizeof(metadata));
    if ((void*)m < chunk_list || (void*)m >= (char*)chunk_list + POOL_SIZE) {
        // pointer not from our pool; ignore (or could call real free)
        return;
    }

    // mark free
    m->status = 0;

    // attempt to coalesce with left neighbor
    if (m->left && m->left->status == 0) {
        // remove left from free list
        remove_meta_from_free_list(m->left);
        // merge left <- m
        metadata *L = m->left;
        L->size = L->size + sizeof(metadata) + m->size;
        L->right = m->right;
        if (m->right) m->right->left = L;
        m = L; // merged chunk's header is L
    }

    // attempt to coalesce with right neighbor
    if (m->right && m->right->status == 0) {
        // remove right from free list
        remove_meta_from_free_list(m->right);
        metadata *R = m->right;
        m->size = m->size + sizeof(metadata) + R->size;
        m->right = R->right;
        if (R->right) R->right->left = m;
    }

    // finally append this free chunk to its multilevel list
    add_meta_to_free_list(m);
}

/* helper used by remove_meta_from_free_list; implemented above */
static int remove_meta_from_free_list(metadata *m); // forward declare
// (we actually implemented it above; this forward is to silence some compilers)

