#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <sys/mman.h>

#define FREE 0
#define USED 1

bool first_malloc = true;
void *chunk_list = NULL; 

typedef struct metadata {
    size_t size;             // 8 bytes (including the size of metadata 32b)
    struct metadata *prev;   // 8 bytes
    struct metadata *next;   // 8 bytes
    unsigned int status;     // 4 bytes (0=free,1=used)
    unsigned int prev_size;  // 4 bytes (size of the previous block)
} metadata; // total = 8+8+8+4+4 = 32

typedef struct layer {
    struct metadata *head;
    struct metadata *tail;
} layer;

layer multilevel_list[12];

int multilevel_index(size_t size) {
    for(int i = 0; i < 12; ++i) {
        if(size <= (32 << i)) {
            return i;
        }
    }
    return 11;
}

void append_to_list(int index, metadata *target) {
    if(multilevel_list[index].head == NULL) {
        multilevel_list[index].head = target;
        multilevel_list[index].tail = target;
        target->prev = NULL;
        target->next = NULL;
    } else {
        multilevel_list[index].tail->next = target;
        target->prev = multilevel_list[index].tail;
        target->next = NULL;
        multilevel_list[index].tail = target;
    }
}

void remove_from_list(int index, metadata *target) {
    if(target->prev != NULL) {
        target->prev->next = target->next;
    } else {
        multilevel_list[index].head = target->next;
    }
    if(target->next != NULL) {
        target->next->prev = target->prev;
    } else {
        multilevel_list[index].tail = target->prev;
    }
    target->prev = NULL;
    target->next = NULL;
}

void *malloc(size_t size) {
    if(first_malloc) {
        first_malloc = false;

        // Pre-allocate a memory pool of 20,000 bytes from the kernel using mmap()
        chunk_list = mmap(NULL, 20000, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
       
        // Initialize metadata for your memory pool
        struct metadata *initial_meta = (struct metadata *)chunk_list;
        initial_meta->size = 20000;
        initial_meta->next = NULL;
        initial_meta->prev = NULL;
        initial_meta->prev_size = 0;
        initial_meta->status = FREE;

        for(int i = 0; i < 12; ++i) {
            multilevel_list[i].head = NULL;
            multilevel_list[i].tail = NULL;
        }
        multilevel_list[11].head = initial_meta;
        multilevel_list[11].tail = initial_meta;
    }

    if (size == 0) {
        // Find largest free chunk
        size_t largest_size = 0;
        for (int i = 11; i >= 0; --i) {
            metadata *current = multilevel_list[i].head;
            while (current != NULL) {
                if (current->status == FREE && current->size > largest_size) {
                    largest_size = current->size;
                }
                current = current->next;
            }
            if (largest_size > 0) break; // found largest
        }

        char buf[64];
        largest_size -= sizeof(metadata); // exclude metadata size
        int len = sprintf(buf, "Max Free Chunk Size = %zu\n", largest_size);
        write(STDOUT_FILENO, buf, len);

        munmap(chunk_list, 20000);
        return NULL;
    }


    // Implementation of malloc using Best Fit with multilevel free list
    size += sizeof(metadata); // need space for metadata
    size = (size + 31) & ~31; // need to round size to multiple of 32

    int index = multilevel_index(size);
    // Find the best fit block in the multilevel free list
    metadata* best_fit = NULL;

    // iterate through the free list starting from the appropriate index
    for(int i = index; i < 12; ++i) {
        metadata *current = multilevel_list[i].head;
        while(current != NULL) {
            if(current->status == FREE) {   // actually, this check is redundant
                if(best_fit == NULL || current->size < best_fit->size) {
                    best_fit = current;
                }
            }
            current = current->next;
        }
        if (best_fit != NULL && best_fit->size == size) {
            break; // perfect fit found
        }
    }

    if(best_fit == NULL) {
        return NULL;    // ERROR: no suitable block found
    }

    // allocate the block
    int old_index = multilevel_index(best_fit->size);
    best_fit->status = USED;

    // Remove from multilevel free list
    remove_from_list(old_index, best_fit);  

    // If the block is larger than needed, split it
    if(best_fit->size > size + sizeof(metadata)) {  // need to be more than size + (new metadata)
        metadata *new_meta = (metadata *)((char *)best_fit + size);
        new_meta->status = FREE;
        new_meta->size = best_fit->size - size;
        new_meta->prev_size = size;

        // Update multilevel free list
        int new_index = multilevel_index(new_meta->size);
        append_to_list(new_index, new_meta);
    } 
    return (void *)((char *)best_fit + sizeof(metadata));
}

void free(void *ptr) {

    metadata* target = (metadata *)((char *)ptr);
    target->status = FREE;

    // check left and right chunks for merging
    metadata* left = (metadata *)((char *)target - target->prev_size);
    metadata* right = (metadata *)((char *)target + target->size);

    if(left != NULL && left != target && left->status == FREE) {
        // Merge with left chunk and need to remove left from free list since we are merging
        left->size += target->size + sizeof(metadata);
        target = left;
        int left_index = multilevel_index(left->size - target->size - sizeof(metadata));
        remove_from_list(left_index, left);
    }

    if(right != NULL && right != target && right - (metadata *)chunk_list < 20000 && right->status == FREE) {
        // Merge with right chunk
        target->size += right->size + sizeof(metadata);
        int right_index = multilevel_index(right->size);
        remove_from_list(right_index, right);
    }

    int index = multilevel_index(target->size);
    // Add the (possibly merged) chunk back to the multilevel free list
    append_to_list(index, target);

    return;
}