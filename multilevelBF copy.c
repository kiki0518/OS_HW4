#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/mman.h>

#define FREE 0
#define USED 1

bool first_malloc = true;

void *chunk_list = NULL; 

int id = 0;

typedef struct metadata {
    size_t size;             // 8 bytes
    struct metadata *prev;   // 8 bytes
    struct metadata *next;   // 8 bytes
    unsigned int status;     // 4 bytes (0=free,1=used)
    unsigned int prev_size;         // 4 bytes (size of the previous block)
} metadata; // total = 8+8+8+4+4 = 32

typedef struct layer {
    struct metadata *head;
    struct metadata *tail;
} layer;

layer multilevel_list[12];

node* IdList[1000]; 

int multilevel_index(size_t size) {
    for(int i = 0; i < 12; ++i) {
        if(size <= (32 << i)) {
            return i;
        }
    }
    return 11;
}

void *malloc(size_t size) {
    if(first_malloc) {
        first_malloc = false;

        // Pre-allocate a memory pool of 20,000 bytes from the kernel using mmap()
        chunk_list = mmap(NULL, 20000, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
       
        // Initialize metadata for your memory pool
        struct metadata *initial_meta = (struct metadata *)chunk_list;
        initial_meta->size = 20000 - sizeof(struct metadata);

        for(int i = 0; i < 12; ++i) {
            multilevel_list[i].head = NULL;
            multilevel_list[i].tail = NULL;
        }

        node initial_node;
        multilevel_list[11].head = &initial_node;
        multilevel_list[11].tail = &initial_node;
        initial_node.next = NULL;
        initial_node.prev = NULL;
        initial_node.curr = initial_meta;

        initial_meta->left = NULL;
        initial_meta->right = NULL;
        initial_meta->status = FREE;
    }

    if(size == 0) {
        // the last fake request, print the size of the largest free chunk
        // int munmap(size_t length; void addr[length], size_t length);*/
        // we can't use printf here, since it may cause deadlock
        sprintf("Largest free chunk size: %zu\n", /* your code to find the largest free chunk */ 0);
        munmap(chunk_list, 20000);
        return NULL;
    }


    // Implementation of malloc using Best Fit with multilevel free list
    size = (size + 31) & ~31; // need to round size to multiple of 32

    int index = multilevel_index(size);
    // Find the best fit block in the multilevel free list
    node* best_fit_node = NULL;
    
    // iterate through the free list starting from the appropriate index
    for(int i = index; i < 12; ++i) {
        node *current = multilevel_list[i].head;
        while(current != NULL) {
            if(current->curr->status == FREE) {
                if(best_fit_node == NULL || current->curr->size < best_fit_node->curr->size) {
                    best_fit_node = current;
                }
            }
            current = current->next;
        }
        if (best_fit_node != NULL && best_fit_node->curr->size == size) {
            break; // perfect fit found
        }
    }

    if(best_fit_node == NULL) {
        // ERROR: no suitable block found
        return NULL;
    }

    // best fit found, let's allocate and split if necessary
    // allocate the block
    int old_index = multilevel_index(best_fit_node->curr->size);
    best_fit_node->curr->status = USED;
    best_fit_node->curr->id = id++;

    // Remove from multilevel free list
    if(best_fit_node->prev != NULL) {
        best_fit_node->prev->next = best_fit_node->next;
    } else {
        multilevel_list[old_index].head = best_fit_node->next;
    }
    if(best_fit_node->next != NULL) {
        best_fit_node->next->prev = best_fit_node->prev;
    } else {
        multilevel_list[old_index].tail = best_fit_node->prev;
    }

    // If the block is larger than needed, split it
    if(best_fit_node->curr->size > size + sizeof(metadata)) {

        node new_node;
        new_node.curr = (metadata *)((char *)best_fit_node + sizeof(metadata) + size);
        new_node.next = best_fit_node->next;
        new_node.prev = best_fit_node;


        metadata *new_meta = (metadata *)((char *)best_fit_node + sizeof(metadata) + size);
        new_meta->size = best_fit_node->curr->size - size - sizeof(metadata);
        new_meta->status = FREE;
        new_meta->left = best_fit_node->curr;
        new_meta->right = best_fit_node->curr->right;
        best_fit_node->curr->right = new_meta;
        best_fit_node->curr->size = size;

        new_node.curr = new_meta;
        new_node.next = best_fit_node->next;
        new_node.prev = best_fit_node;

        // Update multilevel free list
        int new_index = multilevel_index(new_meta->size);
        if(multilevel_list[new_index].head == NULL) {
            multilevel_list[new_index].head = new_node;
            multilevel_list[new_index].tail = new_node;
        } else {
            multilevel_list[new_index].tail->next = new_node;
            new_node.prev = multilevel_list[new_index].tail;
            multilevel_list[new_index].tail = new_node;
        }
    } 

    return 0; // Placeholder return
}

void free(void *ptr) {
    // Your implementation of free
    // need to merge adjacent free chunks

    metadata* target = (metadata *)((char *)ptr);
    target->status = FREE;

    // check left and right chunks for merging



}

    /*
    On the first malloc()
    ⚫ Pre-allocate a memory pool of 20,000 bytes from the kernel 
    using mmap()

    ⚫ Initialize metadata for your memory pool

    ⚫ On subsequent malloc() and free()
    ⚫ Process malloc() and free() within the memory pool
    ⚫ On malloc(0)
    ⚫ A fake request that indicates end-of-test
    ⚫ Print the size of the largest free chunk
    ⚫ Call munmap() to release the memory pool

    void *mmap(size_t length;
                    void addr[length], size_t length, int prot, int flags,
                    int fd, off_t offset);
    */